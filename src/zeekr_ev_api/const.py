import uuid

# Hosts (set to SEA by default)
APP_SERVER_HOST = "https://gateway-pub-hw-em-sg.zeekrlife.com/overseas-app/"
USERCENTER_HOST = "https://gateway-pub-hw-em-sg.zeekrlife.com/zeekr-cuc-idaas-sea/"
MESSAGE_HOST = "https://gateway-pub-hw-em-sg.zeekrlife.com/sea-message-core/"

# EU Hosts
EU_APP_SERVER_HOST = "https://gateway-pub-azure.zeekr.eu/overseas-app/"
EU_USERCENTER_HOST = "https://gateway-pub-azure.zeekr.eu/zeekr-cuc-idaas/"
EU_MESSAGE_HOST = "https://gateway-pub-azure.zeekr.eu/eu-message-core/"

# URLs
LOGIN_URL = "auth/loginByEmailEncrypt"
PROTOCOL_URL = "protocol/service/getProtocol"
SERVICE_URL = "classification/service/type/V2"
URL_URL = "region/url"
CHECKUSER_URL = "auth/checkUserV2"
USERINFO_URL = "user/info"
TSPCODE_URL = "user/tspCode"
BEARERLOGIN_URL = "ms-user-auth/v1.0/auth/login"
VEHLIST_URL = "ms-app-bff/api/v4.0/veh/vehicle-list"
INBOX_URL = "member/inbox/home"
UPDATELANGUAGE_URL = "user/updateLanguage"
SYCN_URL = "open-api/v1/mcs/notice/receiver/equipment/relation/sycn"
VEHICLESTATUS_URL = "ms-vehicle-status/api/v1.0/vehicle/status/latest"
VEHICLECHARGINGSTATUS_URL = "ms-vehicle-status/api/v1.0/vehicle/status/qrvs"
REMOTECONTROLSTATE_URL = "ms-app-bff/api/v1.0/remoteControl/getVehicleState"
REMOTECONTROL_URL = "ms-remote-control/v1.0/remoteControl/control"
CHARGING_LIMIT_URL = "ms-charge-manage/api/v1.0/charge/getLatestSoc"
CHARGE_CONTROL_URL = "ms-charge-manage/api/v1.0/charge/control"
CHARGING_PLAN_URL = "ms-charge-manage/api/v1.0/charge/getChargingPlan"
LATEST_TRAVEL_PLAN_URL = "ms-charge-manage/api/v1.0/charge/getLatestTravelPlan"
SET_CHARGE_PLAN_URL = "ms-charge-manage/api/v1.0/charge/setChargingPlan"
SET_TRAVEL_PLAN_URL = "ms-charge-manage/api/v1.0/charge/setTravelPlan"
JOURNEY_LOG_URL = "ms-vehicle-trail/v1.0/journalLog/trip/listForPage"
TRIP_TRACKPOINTS_URL = "ms-vehicle-trail/v1.0/journalLog/trackpoint/list"

SET_CHARGING_LIMIT_URL = "ms-charge-manage/api/v1.0/charge/setSoc"

# Geo-fencing
FENCE_CREATE_URL = "ms-vehicle-defence/v1/fence/create"
FENCE_DELETE_URL = "ms-vehicle-defence/v1/fence/delete"
FENCE_ENABLE_URL = "ms-vehicle-defence/v1/fence/enable"
FENCE_UPDATE_URL = "ms-vehicle-defence/v1/fence/update"
FENCE_LIST_URL = "ms-vehicle-defence/v1/fence/page"

# Sentry / Dashcam
SENTRY_EVENTS_URL = "sentinel-monitoring-service/api/v1/alarm/event/query"
SENTRY_PICS_URL = "sentinel-monitoring-service/api/v1/pic/list"

COUNTRY_CODE = "NL"
REGION_CODE = "EU"

REGION_LOGIN_SERVERS = {
    "SEA": "https://sea-snc-tsp-api-gw.zeekrlife.com/",
    "UAE": "https://me-snc-tsp-api-gw.zeekrlife.com/",
    "LA": "https://la-snc-tsp-api-gw.zeekrlife.com/",
    "EU": "https://eu-snc-tsp-api-gw.zeekrlife.com/",
}

# Secrets
HMAC_ACCESS_KEY = "ca5f8b2b6ef3487e9de345122190935a"  # from libenv.so (OLLVM-encrypted, EU/PROD)
HMAC_SECRET_KEY = "woaghirrd8bcf0416d524691988df5fe7fc02362"  # from libenv.so (OLLVM-encrypted, EU/PROD)
PASSWORD_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCBzg6+dwMVtGTNo8EPL+XFyz0OY0pMMo3HdRZGauuCSgISfVMkMmOhNEb2q9UfiQcEeOwVmOgts9VF4q0BJYrRNGQaPkLybwkWsx1JmbBRcr3qq+WWhqq8xQFksfn8KeXmwgVMFX+bzup43LE0vy0yyb+SuQ9FBBGuE1d/BfHHpQIDAQAB"  # RSA-1024 from v2.9.9 DEX
PROD_SECRET = "890efe3207af95348b95f66b2ee7da04"  # from SignInterceptor (v2.9.9 PROD signing key)
VIN_KEY = "a01a6db985a2f5d4"  # from libcrypto-util.so (AES key for VIN encryption)
VIN_IV = "ed446b8b8845013d"  # from libcrypto-util.so (AES IV for VIN encryption)

DEFAULT_HEADERS = {
    "accept-encoding": "gzip",
    "accept-language": "en-AU",
    "app-authorization": "1003",
    "app-code": "32816dbd-ff17-47b7-e250-5dae7d9f8cd4",
    "appcode": "eu-app",
    "appid": "TSP",
    "appsecret": "zeekr_tis",
    "appversion": "2.9.9",
    "call-source": "android",
    "client-id": "1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc",
    "Content-Type": "application/json; charset=UTF-8",
    "country": COUNTRY_CODE,
    "device-name": "sdk_gphone64_x86_64",
    "device-type": "app",
    "language": "en",
    "msgappid": "11002",
    "msgclientid": "1003",
    "registcountry": COUNTRY_CODE,
    "tmp-tenant-code": "3300743799505195008",
    "user-agent": "Device/GoogleAppName/com.zeekr.overseasAppVersion/2.9.9Platform/androidOSVersion/16Ditto/true",
}

LOGGED_IN_HEADERS = {
    "Accept-Encoding": "gzip",
    "ACCEPT-LANGUAGE": "en-AU",
    "AppId": "ONEX97FB91F061405",
    "authorization": "",
    "Content-Type": "application/json; charset=UTF-8",
    "user-agent": "okhttp/4.12.0",
    "X-API-SIGNATURE-VERSION": "2.0",
    "X-APP-ID": "ZEEKRCNCH001M0001",
    "x-app-os-version": "",
    "x-device-id": str(uuid.uuid4()),
    "x-p": "Android",
    "X-PLATFORM": "APP",
    "X-PROJECT-ID": "ZEEKR_SEA",
}
