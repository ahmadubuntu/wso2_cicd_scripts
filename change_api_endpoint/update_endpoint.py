#!/usr/bin/env python3
import requests, sys, json
from configparser import ConfigParser
from urllib.parse import urljoin
from requests.auth import HTTPBasicAuth

cfg = ConfigParser()
cfg.read('config.ini')

BASE_URL = cfg.get('apim', 'base_url').rstrip('/')
DCR_URL = cfg.get('apim', 'dcr_url').rstrip('/')
TOKEN_URL = cfg.get('apim', 'token_url').rstrip('/')
ADMIN_USER = cfg.get('apim', 'admin_username')
ADMIN_PASS = cfg.get('apim', 'admin_password')
SCOPES = cfg.get('apim', 'scopes').strip()
SERVICE_CATALOG_URL = cfg.get('apim', 'service_catalog_url', fallback=None)
SERVICE_CATALOG_AUTH = cfg.get('apim', 'service_catalog_auth', fallback='none').lower()
SERVICE_CATALOG_USER = cfg.get('apim', 'service_catalog_user', fallback=None)
SERVICE_CATALOG_PASSWORD = cfg.get('apim', 'service_catalog_password', fallback=None)
VERIFY_SSL = cfg.getboolean('apim', 'verify_ssl', fallback=True)

def register_client():
    """DCR request to get clientId and clientSecret"""
    payload = {
        "callbackUrl": "www.google.lk",
        "clientName": "rest_api_publisher",
        "owner": ADMIN_USER,
        "grantType": "password client_credentials refresh_token",
        "saasApp": True
    }
    auth = HTTPBasicAuth(ADMIN_USER, ADMIN_PASS)
    try:
        r = requests.post(DCR_URL, json=payload, auth=auth, verify=VERIFY_SSL, timeout=30)
        r.raise_for_status()
        data = r.json()
        client_id = data.get('clientId')
        client_secret = data.get('clientSecret')
        if not client_id or not client_secret:
            print("DCR پاسخ معتبری نداد:", json.dumps(data, indent=2))
            sys.exit(1)
        print(f"DCR موفق. clientId={client_id}")
        return client_id, client_secret
    except requests.RequestException as e:
        print("خطا در ثبت DCR:", e)
        sys.exit(1)

def obtain_token(client_id, client_secret):
    """Get access token via password grant"""
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    auth = HTTPBasicAuth(client_id, client_secret)
    data = {
        'grant_type': 'password',
        'username': ADMIN_USER,
        'password': ADMIN_PASS,
        'scope': SCOPES
    }
    try:
        r = requests.post(TOKEN_URL, data=data, headers=headers, auth=auth, verify=VERIFY_SSL, timeout=30)
        r.raise_for_status()
        token = r.json().get('access_token')
        if not token:
            print("پاسخ توکن معتبر نبود:", r.text)
            sys.exit(1)
        print("توکن دریافت شد.")
        print(token)
        return token
    except requests.RequestException as e:
        print("خطا در گرفتن توکن:", e)
        sys.exit(1)

def auth_headers(token):
    return {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}

def list_apis(token, limit=1000):
    url = urljoin(BASE_URL + '/', 'api/am/publisher/v4/apis')
    r = requests.get(url, headers=auth_headers(token), params={'limit': limit}, verify=VERIFY_SSL)
    r.raise_for_status()
    data = r.json()
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if 'list' in data:
            return data['list']
        if 'apis' in data:
            return data['apis']
        return [data]
    return []

def get_api(token, api_id):
    url = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}')
    r = requests.get(url, headers=auth_headers(token), verify=VERIFY_SSL)
    r.raise_for_status()
    return r.json()

def list_gateway_environments(token):
    """
    Try multiple possible endpoints to get gateway environments and return list of environments.
    Uses auth_headers(token).
    """
    possible_paths = [
        'api/am/admin/v4/environments',
        'api/am/publisher/v4/gateway-environments',
        'api/am/publisher/v4/environments',
        'api/am/publisher/v1/environments',
        'api/am/publisher/v1/gateway-environments',
        'api/am/publisher/v3/environments'
    ]
    headers = auth_headers(token)
    for p in possible_paths:
        url = urljoin(BASE_URL + '/', p)
        try:
            r = requests.get(url, headers=headers, verify=VERIFY_SSL, timeout=20)
        except requests.RequestException as e:
            print(f"خطا هنگام فراخوانی {url}: {e}")
            continue

        if r.status_code == 200:
            try:
                j = r.json()
            except Exception:
                print(f"پاسخ از {url} JSON نبود، متن پاسخ (کوتاه): {r.text[:300]}")
                continue

            # possible keys
            if isinstance(j, dict):
                for key in ('list', 'environments', 'gatewayEnvironments', 'items'):
                    if key in j and isinstance(j[key], list):
                        return j[key]
            if isinstance(j, list):
                return j

            print(f"پاسخ 200 از {url} اما ساختار غیرمنتظره. نمونه:")
            print(json.dumps(j, indent=2)[:1000])
            return []

        else:
            print(f"پاسخ از {url}: HTTP {r.status_code}")
            if r.status_code == 401:
                print("→ 401 Unauthorized: مطمئن شوید توکن scope لازم (مثلاً admin scopes) را دارد.")
            continue

    print("نتوانستم هیچ gateway environment معتبری پیدا کنم. مسیرهای امتحان‌شده را بررسی کنید.")
    return []

# ------------ افزودن: undeploy + لیست + حذف ایمن ریویژن‌ها --------------

def list_revisions(token, api_id):
    """
    GET /api/am/publisher/v4/apis/{apiId}/revisions
    Returns list of revision dicts (or [] on error).
    """
    url = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}/revisions')
    try:
        r = requests.get(url, headers=auth_headers(token), verify=VERIFY_SSL, timeout=20)
        if r.status_code != 200:
            print(f"خطا در گرفتن لیست revision ها: HTTP {r.status_code}. بدنه پاسخ: {r.text[:500]}")
            return []
        j = r.json()
        if isinstance(j, dict) and 'list' in j and isinstance(j['list'], list):
            return j['list']
        if isinstance(j, list):
            return j
        if isinstance(j, dict):
            cand = []
            for v in j.values():
                if isinstance(v, dict) and ('id' in v or 'revisionUuid' in v or 'revisionId' in v):
                    cand.append(v)
            if cand:
                return cand
        return []
    except Exception as e:
        print("Exception در list_revisions:", e)
        return []

def undeploy_revision(token, api_id, revision_id, all_environments=False):
    """
    Robust undeploy: try several request shapes until one succeeds.
    Returns True on success, False otherwise.
    """
    headers = auth_headers(token)
    headers['Content-Type'] = 'application/json'
    base_path = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}/undeploy-revision')
    attempts = []

    # Method A: POST body with revisionUuid (common)
    try:
        payload = [{"revisionUuid": revision_id}]
        params = {'allEnvironments': 'true'} if all_environments else {}
        r = requests.post(base_path, headers=headers, params=params, data=json.dumps(payload), verify=VERIFY_SSL, timeout=20)
        attempts.append(('POST body revisionUuid', r.status_code, r.text[:1000]))
        if r.status_code in (200,201,202):
            print("undeploy succeeded using POST body revisionUuid.")
            return True
    except Exception as e:
        attempts.append(('POST body revisionUuid exception', str(e), ''))

    # Method B: POST body with revisionId (different field name)
    try:
        payload = [{"revisionId": revision_id}]
        params = {'allEnvironments': 'true'} if all_environments else {}
        r = requests.post(base_path, headers=headers, params=params, data=json.dumps(payload), verify=VERIFY_SSL, timeout=20)
        attempts.append(('POST body revisionId', r.status_code, r.text[:1000]))
        if r.status_code in (200,201,202):
            print("undeploy succeeded using POST body revisionId.")
            return True
    except Exception as e:
        attempts.append(('POST body revisionId exception', str(e), ''))

    # Method C: use query parameter (some implementations expect ?revisionId=...)
    try:
        params = {'revisionId': revision_id}
        if all_environments:
            params['allEnvironments'] = 'true'
        r = requests.post(base_path, headers=headers, params=params, data=json.dumps([]), verify=VERIFY_SSL, timeout=20)
        attempts.append(('POST with query revisionId', r.status_code, r.text[:1000]))
        if r.status_code in (200,201,202):
            print("undeploy succeeded using POST + query revisionId.")
            return True
    except Exception as e:
        attempts.append(('POST query revisionId exception', str(e), ''))

    # Method D: DELETE endpoint (some versions accept deletion of deployment)
    try:
        del_url = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}/revisions/{revision_id}/deployments')
        r = requests.delete(del_url, headers=headers, verify=VERIFY_SSL, timeout=20)
        attempts.append(('DELETE /revisions/{id}/deployments', r.status_code, r.text[:1000]))
        if r.status_code in (200,204):
            print("undeploy succeeded using DELETE /revisions/{id}/deployments.")
            return True
    except Exception as e:
        attempts.append(('DELETE deployments exception', str(e), ''))

    # Method E: Try alternate undeploy path (older/newer APIs)
    alt_paths = [
        urljoin(BASE_URL + '/', f'api/am/publisher/v3/apis/{api_id}/undeploy-revision'),
        urljoin(BASE_URL + '/', f'api/am/publisher/v1/apis/{api_id}/undeploy-revision'),
        urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}/revisions/{revision_id}/undeploy'),
    ]
    for p in alt_paths:
        try:
            r = requests.post(p, headers=headers, data=json.dumps([{"revisionUuid": revision_id}]), verify=VERIFY_SSL, timeout=20)
            attempts.append((f'POST alt {p}', r.status_code, r.text[:1000]))
            if r.status_code in (200,201,202):
                print(f"undeploy succeeded using alt path {p}")
                return True
        except Exception as e:
            attempts.append((f'POST alt {p} exception', str(e), ''))

    print("حذف deployment ناموفق. تلاش‌های انجام‌شده (summary):")
    for a in attempts:
        name, status_or_err, body = a
        print(f"- {name}: {status_or_err}")
        if isinstance(status_or_err, int):
            print("  body:", body[:800])
    cur = list_revisions(token, api_id)
    print("در حال حاضر ریویژن‌ها (debug):")
    try:
        print(json.dumps(cur, indent=2)[:2000])
    except Exception:
        print(cur)
    return False

def delete_revision(token, api_id, revision_id):
    """
    DELETE /api/am/publisher/v4/apis/{apiId}/revisions/{revisionId}
    Returns True on success.
    """
    url = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}/revisions/{revision_id}')
    try:
        r = requests.delete(url, headers=auth_headers(token), verify=VERIFY_SSL, timeout=20)
    except requests.RequestException as e:
        print("خطا هنگام حذف revision:", e)
        return False
    if r.status_code in (200, 204):
        print(f"Revision {revision_id} حذف شد.")
        return True
    else:
        print(f"حذف revision {revision_id} ناموفق. Status={r.status_code}")
        try:
            print(json.dumps(r.json(), indent=2))
        except Exception:
            print(r.text[:1000])
        return False

def ensure_revision_capacity(token, api_id, limit=5):
    """
    Ensure number of revisions < limit.
    If >= limit, attempts to undeploy then delete the oldest revisions until capacity is available.
    Returns True if capacity ensured (i.e. len < limit), False otherwise.
    """
    revs = list_revisions(token, api_id)
    print("DEBUG REVISIONS:", json.dumps(revs, indent=2))
    if not isinstance(revs, list):
        print("خطا: لیست revisionها نامعتبر است:", revs)
        return False
    if len(revs) < limit:
        return True

    def rev_time_key(r):
        for k in ('deploymentTime', 'createdTime', 'timestamp', 'created'):
            if k in r and r.get(k):
                return r.get(k)
        return r.get('id') or r.get('revisionUuid') or r.get('revisionId') or ''

    sorted_revs = sorted(revs, key=rev_time_key)
    while len(sorted_revs) >= limit:
        oldest = sorted_revs.pop(0)
        rid = oldest.get('id') or oldest.get('revisionUuid') or oldest.get('revisionId')
        if not rid:
            print("نمیتوانم id ریویژن قدیمی را تشخیص دهم، اسکپ می‌کنم:", oldest)
            continue

        deployed = False
        for key in ('deployed', 'deployedEnvironments', 'deployments', 'deploymentInfo'):
            val = oldest.get(key)
            if val:
                if (isinstance(val, list) and len(val) > 0) or (isinstance(val, dict) and len(val) > 0) or (val is True):
                    deployed = True
                    break

        if deployed:
            print(f"اول undeploy ریویژن {rid} (قدیمی‌ترین) انجام می‌دم چون مستقره...")
            ok_ud = undeploy_revision(token, api_id, rid, all_environments=True)
            if not ok_ud:
                print("undeploy موفق نبود؛ نمی‌توانم ادامه بدهم.")
                return False
            import time
            time.sleep(1)

        print(f"در حال حذف revision {rid} ...")
        ok_del = delete_revision(token, api_id, rid)
        if not ok_del:
            print("حذف ناموفق ماند؛ خروج با خطا.")
            return False

        revs = list_revisions(token, api_id)
        sorted_revs = sorted(revs, key=rev_time_key) if revs else []

    final_revs = list_revisions(token, api_id)
    if len(final_revs) < limit:
        return True
    print("بعد از تلاش برای حذف، همچنان ظرفیت کافی یافت نشد.")
    return False

# --- توابع مربوط به Revision / Deploy ---
def create_revision(token, api_id, description=None):
    """
    Create a new revision for the given API.
    Returns the created revision id/uuid string.
    Endpoint: POST /api/am/publisher/v4/apis/{apiId}/revisions
    """
    url = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}/revisions')
    payload = {}
    if description:
        payload['description'] = description
    headers = auth_headers(token)
    headers['Content-Type'] = 'application/json'
    try:
        r = requests.post(url, headers=headers, data=json.dumps(payload), verify=VERIFY_SSL, timeout=30)
        r.raise_for_status()
        j = r.json()
        for key in ('revisionId', 'revisionUuid', 'id', 'revision'):
            if isinstance(j, dict) and key in j:
                return j[key]
        if isinstance(j, dict):
            if 'revision' in j and isinstance(j['revision'], dict):
                for k in ('id','revisionId','revisionUuid'):
                    if k in j['revision']:
                        return j['revision'][k]
        if isinstance(j, str):
            return j
        if isinstance(j, list) and j:
            first = j[0]
            if isinstance(first, dict):
                for k in ('id','revisionId','revisionUuid'):
                    if k in first:
                        return first[k]
        print("Warning: couldn't detect revision id in create-revision response. Full response:")
        print(json.dumps(j, indent=2))
        return None
    except requests.RequestException as e:
        print("خطا هنگام ایجاد revision:", e)
        if 'r' in locals():
            print("Response:", getattr(r, 'text', ''))
        return None

def deploy_revision(token, api_id, revision_id, gateway_name=None, vhost="", displayOnDevportal=True, has_sandbox=True):
    """
    Deploy revision:
      - اگر gateway environments پیدا شدند: فقط یک‌بار شماره محیط را از کاربر می‌پرسد،
        و اگر vhost خالی بود از اولین vhost آن محیط استفاده می‌کند.
      - اگر محیطی پیدا نشد: از کاربر gateway_name و vhost را می‌پرسد (fallback interactive).
      - پارامتر has_sandbox برای اطلاع تابع است ولی در اینجا تنها جهت اطلاع استفاده می‌شود.
    """
    headers = auth_headers(token)
    headers['Content-Type'] = 'application/json'

    # تلاش برای کشف محیط‌ها
    envs = list_gateway_environments(token)

    if envs:
        # نمایش و انتخاب محیط — فقط یکبار پرسیده می‌شود
        print("\nGateway Environments:")
        for i, env in enumerate(envs, start=1):
            vhosts = []
            if isinstance(env.get('vhosts'), list):
                vhosts = [vh.get('host') for vh in env.get('vhosts', [])]
            print(f"  {i}) {env.get('name') or env.get('displayName') or env.get('gatewayName')} (vhosts: {vhosts})")

        sel = input("شماره environment برای deploy انتخاب کن (یا q برای خروج, پیش‌فرض 1): ").strip()
        if sel.lower() == 'q':
            return False
        if not sel:
            sel = '1'
        try:
            chosen = envs[int(sel)-1]
        except Exception:
            print("انتخاب نامعتبر.")
            return False

        gateway_name = gateway_name or (chosen.get('name') or chosen.get('displayName') or chosen.get('gatewayName'))
        # اگر vhost خالی است، از اولین vhost محیط استفاده کن (اگر وجود داشته باشد)
        if not vhost:
            vh = chosen.get('vhosts') or chosen.get('vhost') or []
            if isinstance(vh, list) and vh:
                vhost = vh[0].get('host') if isinstance(vh[0], dict) else vh[0]
            elif isinstance(vh, str):
                vhost = vh

    else:
        # fallback interactive: چون محیط‌ها کشف نشدند، gateway_name و vhost را از کاربر بپرس
        print("⚠️ نتوانستم gateway environments را کشف کنم. لطفاً اطلاعات را وارد کن.")
        gateway_name = gateway_name or input("نام Gateway را وارد کن (مثلاً 'Default'): ").strip() or "Default"
        vhost = vhost or input("vhost برای deploy (مثلاً 'gw-stg.charisma.digital') — خالی بگذار اگر نامشخص است: ").strip()
        display = input("نمایش در Dev Portal؟ [Y/n]: ").strip().lower() or "y"
        displayOnDevportal = (display == 'y')

    # ساخت آیتم payload (بدون تکرار سوالات)
    item = {
        "name": gateway_name,
        "vhost": vhost,
        "displayOnDevportal": bool(displayOnDevportal)
    }
    url = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}/deploy-revision')

    attempts = []

    # Attempt A: revisionUuid inside array item
    payload_a = [{ **item, "revisionUuid": revision_id }]
    print("\n--- Attempt A: POST with revisionUuid inside array item ---")
    print("curl equivalent:")
    print(f"curl -k -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' -X POST '{url}' -d '{json.dumps(payload_a)}'")
    try:
        r = requests.post(url, headers=headers, data=json.dumps(payload_a), verify=VERIFY_SSL, timeout=30)
        attempts.append(('A', r.status_code, r.text[:2000]))
        if r.status_code in (200,201,202):
            try:
                print("Deploy OK (Attempt A). Response:", json.dumps(r.json(), indent=2))
            except Exception:
                print("Deploy OK (Attempt A). Response text:", r.text)
            return True
        else:
            print(f"Attempt A returned {r.status_code}. Body:")
            try:
                print(json.dumps(r.json(), indent=2))
            except Exception:
                print(r.text)
    except Exception as e:
        print("Attempt A exception:", e)
        attempts.append(('A-exc', str(e), ''))

    # Attempt B: ?revisionId=... and body array
    params_b = {'revisionId': revision_id}
    payload_b = [ item ]
    print("\n--- Attempt B: POST with ?revisionId=... and body array of items ---")
    print("curl equivalent:")
    print(f"curl -k -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' -X POST '{url}?revisionId={revision_id}' -d '{json.dumps(payload_b)}'")
    try:
        r = requests.post(url, headers=headers, params=params_b, data=json.dumps(payload_b), verify=VERIFY_SSL, timeout=30)
        attempts.append(('B', r.status_code, r.text[:2000]))
        if r.status_code in (200,201,202):
            try:
                print("Deploy OK (Attempt B). Response:", json.dumps(r.json(), indent=2))
            except Exception:
                print("Deploy OK (Attempt B). Response text:", r.text)
            return True
        else:
            print(f"Attempt B returned {r.status_code}. Body:")
            try:
                print(json.dumps(r.json(), indent=2))
            except Exception:
                print(r.text)
    except Exception as e:
        print("Attempt B exception:", e)
        attempts.append(('B-exc', str(e), ''))

    # Attempt C: revisionId inside array item
    payload_c = [ { **item, "revisionId": revision_id } ]
    print("\n--- Attempt C: POST with revisionId inside array item ---")
    print("curl equivalent:")
    print(f"curl -k -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' -X POST '{url}' -d '{json.dumps(payload_c)}'")
    try:
        r = requests.post(url, headers=headers, data=json.dumps(payload_c), verify=VERIFY_SSL, timeout=30)
        attempts.append(('C', r.status_code, r.text[:2000]))
        if r.status_code in (200,201,202):
            try:
                print("Deploy OK (Attempt C). Response:", json.dumps(r.json(), indent=2))
            except Exception:
                print("Deploy OK (Attempt C). Response text:", r.text)
            return True
        else:
            print(f"Attempt C returned {r.status_code}. Body:")
            try:
                print(json.dumps(r.json(), indent=2))
            except Exception:
                print(r.text)
    except Exception as e:
        print("Attempt C exception:", e)
        attempts.append(('C-exc', str(e), ''))

    # diagnostics: admin envs
    alt_admin_url = urljoin(BASE_URL + '/', f'api/am/admin/v4/environments')
    try:
        r_env = requests.get(alt_admin_url, headers=headers, verify=VERIFY_SSL, timeout=20)
        print(f"Admin environments fetch status: {r_env.status_code}")
        try:
            print(r_env.json())
        except Exception:
            print(r_env.text[:1000])
    except Exception:
        pass

    # All failed
    print("\nAll deploy attempts failed. Summary of attempts (short):")
    for a in attempts:
        name, status_or_err, body = a
        print(f"- {name}: {status_or_err}")
        if isinstance(status_or_err, int):
            print("  body:", body[:1000])
    print("برای دیباگ بیشتر لطفاً لاگ‌های wso2carbon.log و gateway log را بررسی کنید.")
    return False

def update_api(token, api_id, payload):
    url = urljoin(BASE_URL + '/', f'api/am/publisher/v4/apis/{api_id}')
    headers = auth_headers(token)
    headers['Content-Type'] = 'application/json'
    
    # داده‌ها را به JSON تبدیل می‌کند
    json_data = json.dumps(payload, indent=2)
    
    print("\n--- Command Curl Equivalent for Debugging ---")
    # 💡 نمایش دستور Curl
    curl_command = (
        f"curl -X PUT \\\n"
        f"  '{url}' \\\n"
        f"  -H 'Authorization: Bearer {token}' \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -d @-"
    )
    print(curl_command)
    print("\n--- JSON Payload ---")
    print(json_data)
    print("------------------------------------------")

    try:
        r = requests.put(url, headers=headers, data=json_data, verify=VERIFY_SSL)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as e:
        # 💡 مدیریت خطای بهتر برای نمایش پاسخ سرور
        print(f"\n❌ HTTP Error {r.status_code}: خطای سرور هنگام به‌روزرسانی API.")
        print("متن پاسخ سرور (احتمالاً شامل جزئیات خطا):")
        try:
            # سعی می‌کند پاسخ را به صورت JSON زیبا نمایش دهد
            error_details = r.json()
            print(json.dumps(error_details, indent=2))
        except json.JSONDecodeError:
            # اگر پاسخ JSON نبود، متن خام را نمایش می‌دهد
            print(r.text)
        
        sys.exit(1) # خروج با کد خطا
        

def list_services(token):
    headers = auth_headers(token)
    
    try:
        response = requests.get(SERVICE_CATALOG_URL, headers=headers, verify=VERIFY_SSL)
    except requests.exceptions.RequestException as e:
        print("خطا هنگام فراخوانی سرویس کاتالوگ:", e)
        sys.exit(1)

    if response.status_code != 200:
        print(f"Service catalog پاسخ غیر 200 داد: {response.status_code}")
        print("متن پاسخ:", response.text[:500])
        sys.exit(1)

    try:
        data = response.json()
        
        # 💡 اصلاح: اگر داده حاوی کلید 'list' است، فقط محتوای آن را برگردان
        if isinstance(data, dict) and 'list' in data:
            return data['list']
        
        # در غیر این صورت، همان داده را برگردان
        return data 
        
    except Exception:
        print("Service catalog پاسخ JSON معتبر برنگرداند. متن پاسخ:")
        print(response.text[:1000])
        sys.exit(1)


def choose_from_list(items, label_fn):
    for i, it in enumerate(items, start=1):
        print(f"{i:3d}) {label_fn(it)}")
    sel = input("Enter number (or q to quit): ").strip()
    if sel.lower() == 'q':
        sys.exit(0)
    try:
        idx = int(sel) - 1
        if idx < 0 or idx >= len(items):
            raise ValueError()
        return items[idx]
    except Exception:
        print("انتخاب نامعتبر، دوباره تلاش کن.")
        return choose_from_list(items, label_fn)

def main():
    # 1) DCR
    client_id, client_secret = register_client()
    # 2) Token
    token = obtain_token(client_id, client_secret)
    # 3) APIs
    apis = list_apis(token)
    if not apis:
        print("هیچ API ای یافت نشد.")
        return
    print("\nAPIs:")
    chosen_api = choose_from_list(apis, lambda a: f"{a.get('name') or a.get('id')} - {a.get('version','')} ({a.get('id')})")
    api_id = chosen_api.get('id') or chosen_api.get('uuid') or chosen_api.get('apiId')
    api_obj = get_api(token, api_id)
    print("\nSelected API:")
    print(json.dumps({k: api_obj.get(k) for k in ('name','id','version','endpointConfig')}, indent=2))

    # 4) Services
    services = list_services(token)
    if not isinstance(services, list) or not services:
        print("Service catalog پاسخ نامعتبر یا خالی داد:", json.dumps(services, indent=2))
        sys.exit(1)
    print("\nServices:")
    chosen_svc = choose_from_list(services, lambda s: f"{s.get('name','<no-name>')} - {s.get('version','<no-version>')} - {s.get('serviceUrl','<no-url>')} ({s.get('id','')})")
    svc_url = chosen_svc.get('serviceUrl')

    # # 5) Update endpointConfig
    # # new_endpoint_config = {
    # #     "endpoint_type": "http",
    # #     "production_endpoints": {"url": svc_url, "config": None},
    # #     "sandbox_endpoints": {"url": svc_url, "config": None}
    # # }
    # new_endpoint_config = {
    #     "endpoint_type": "http",
    #     "production_endpoints": {"url": svc_url, "config": {}},
    #     "sandbox_endpoints": {"url": svc_url, "config": {}}
    # }
    # # api_obj['endpointConfig'] = json.dumps(new_endpoint_config)
    # api_obj['endpointConfig'] = new_endpoint_config

    # confirm = input(f"\nمی‌خوای endpoint API '{api_obj.get('name')}' را به '{svc_url}' تغییر بدهم؟ [y/N]: ").strip().lower()
    # if confirm != 'y':
    #     print("Aborted.")
    #     return

    # updated = update_api(token, api_id, api_obj)
    # print("بروزرسانی موفق بود. پاسخ (partial):")
    # print(json.dumps({k: updated.get(k) for k in ('name','id','version','endpointConfig')}, indent=2))

    # 5) Update endpointConfig
    # تصمیم می‌گیریم فقط در صورتی sandbox را ست کنیم که قبلاً موجود بوده باشد.
    # ابتدا وضعیت قبلی endpointConfig را بخوان
    endpoint_cfg_orig = api_obj.get('endpointConfig') or {}
    if isinstance(endpoint_cfg_orig, str):
        try:
            endpoint_cfg_orig = json.loads(endpoint_cfg_orig)
        except Exception:
            endpoint_cfg_orig = {}

    # تشخیص وجود sandbox در کانفیگ پیشین
    sandbox_exists = False
    try:
        sd_orig = endpoint_cfg_orig.get('sandbox_endpoints') or endpoint_cfg_orig.get('sandboxEndpoints') or {}
        if isinstance(sd_orig, dict) and sd_orig.get('url'):
            sandbox_exists = True
    except Exception:
        sandbox_exists = False

    # ساخت new_endpoint_config فقط با production، و تنها در صورت نیاز sandbox را اضافه کن
    new_endpoint_config = {
        "endpoint_type": "http",
        "production_endpoints": {"url": svc_url, "config": {}}
    }
    if sandbox_exists:
        # اگر قبلاً sandbox وجود داشت، آن را هم به‌روزرسانی کن
        new_endpoint_config["sandbox_endpoints"] = {"url": svc_url, "config": {}}

    # جایگزین کن در شی API (اگر سرویس قبلاً endpointConfig را به صورت متن داشت، به همان شکل حفظ نکن)
    api_obj['endpointConfig'] = new_endpoint_config

    confirm = input(f"\nمی‌خوای endpoint API '{api_obj.get('name')}' را به '{svc_url}' تغییر بدهم؟ [y/N]: ").strip().lower()
    if confirm != 'y':
        print("Aborted.")
        return

    updated = update_api(token, api_id, api_obj)
    print("بروزرسانی موفق بود. پاسخ (partial):")
    print(json.dumps({k: updated.get(k) for k in ('name','id','version','endpointConfig')}, indent=2))







    # # 6) Create Revision و Deploy 
    # print("بروزرسانی موفق بود. اکنون revision جدید می‌سازیم و آن را دیپلوی می‌کنیم...")
    # desc = input("در صورت خواستن توضیح برای revision وارد کن (یا Enter برای بدون توضیح): ").strip() or None
    # # اطمینان از ظرفیت ریویژن‌ها
    # # ensure_revision_capacity(token, api_id, keep=4)
    # ok_capacity = ensure_revision_capacity(token, api_id, limit=5)
    # if not ok_capacity:
    #     print("ظرفیت ریویژن‌ها پر است و نتوانستم قدیمی‌ها را پاک کنم. خروج.")
    #     sys.exit(1)

    # revision_id = create_revision(token, api_id, description=desc)
    # if not revision_id:
    #     print("ایجاد revision ناموفق بود. خروج.")
    #     sys.exit(1)
    # print(f"Revision ایجاد شد: {revision_id}")

    # # # انتخاب Gateways: پیش‌فرض 'Default' است — میتوانید این را از کاربر بپرسید یا لیست محیط‌ها را فراخوانی کنید
    # # gateway = input("نام Gateway environment برای دیپلوی (پیش‌فرض 'Default'): ").strip() or "Default"
    # # vhost = input("vhost برای دیپلوی (در صورت نیاز، خالی بگذارید): ").strip() or ""
    # # display = input("نمایش در Dev Portal؟ [Y/n] (پیش‌فرض Y): ").strip().lower()
    # # display_flag = False if display == 'n' else True

    # # ok = deploy_revision(token, api_id, revision_id, gateway_name=gateway, vhost=vhost, displayOnDevportal=display_flag)
    # # if not ok:
    # #     print("Deploy ناموفق بود. لطفاً لاگ‌ها و پاسخ سرور را چک کن.")
    # #     sys.exit(1)
    # # print("Revision با موفقیت دیپلوی شد.")



    # ---------- revision management ----------
    # Ensure capacity (will undeploy+delete old revisions if needed)
    ok_capacity = ensure_revision_capacity(token, api_id, limit=5)
    if not ok_capacity:
        print("ظرفیت ریویژن‌ها پر است و نتوانستم قدیمی‌ها را پاک کنم. خروج.")
        sys.exit(1)

    # create revision
    print("بروزرسانی موفق بود. اکنون revision جدید می‌سازیم و آن را دیپلوی می‌کنیم...")
    desc = input("در صورت خواستن توضیح برای revision وارد کن (یا Enter برای بدون توضیح): ").strip() or None
    revision_id = create_revision(token, api_id, description=desc)
    if not revision_id:
        print("ایجاد revision ناموفق بود. خروج.")
        sys.exit(1)
    print("Revision ایجاد شد:", revision_id)

    # determine if sandbox exists (used only to inform, deploy_revision handles prompting)
    endpoint_cfg = updated.get('endpointConfig') or {}
    if isinstance(endpoint_cfg, str):
        try:
            endpoint_cfg = json.loads(endpoint_cfg)
        except Exception:
            endpoint_cfg = {}
    sd = endpoint_cfg.get('sandbox_endpoints') or endpoint_cfg.get('sandboxEndpoints') or {}
    sandbox_exists = bool(sd and isinstance(sd, dict) and sd.get('url'))

    # single call to deploy_revision (no prior vhost/display questions)
    ok = deploy_revision(token, api_id, revision_id, gateway_name=None, vhost="", displayOnDevportal=True, has_sandbox=sandbox_exists)
    if not ok:
        print("Deploy ناموفق بود. لطفاً لاگ‌ها و پاسخ سرور را چک کن.")
        sys.exit(1)
    print("Revision با موفقیت دیپلوی شد.")



if __name__ == '__main__':
    main()
