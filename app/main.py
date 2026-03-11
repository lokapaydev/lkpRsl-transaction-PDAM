# pylint: disable=no-member, assignment-from-no-return
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
import ast
import json
import os
import random
import string
import time
import uuid

import base58
import jwt
import redis
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from google.cloud import firestore
from google.cloud import pubsub_v1
from google.oauth2 import service_account
from pydantic import BaseModel
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as signature_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

print("DEBUG - CONTAINER IS STARTING....")

app = FastAPI()
_firestore_client = None
GMT_PLUS_7 = timezone(timedelta(hours=7))

with open("coreSystemPublicKeyEd25519.pem", "rb") as f:
    coreSystemPublicKeyEd25519 = serialization.load_pem_public_key(f.read())

deploymentTarget = "cloud-dev"

if deploymentTarget == "local":
    DOTENV_FILE = ".env-dev"
    hexKey = "d13bc2164d9bee84e54f8c8b56ea4fe79a777f0014120ff7182b076d6e6464f6"
    ivHex = "80d726ebc538cb6fefb270e4f66deade"
    project_id = "lokapay-reseller-tmis"
    encryptedPrivateKeyHex = "39b7e73a44715c814a645847504462bbf85897d5f12f1e64f47e3710c5d440cdde0ae35620bd1ca52671b5d11742702882029bb9c7bb2bcf0d72b86a0a2fc1058c89192be608febbbc56e9ea6044a53471dc4cf563c52513b833b8d357b220a2c4c18eff6d39b1ad0811e508c2151f1b4bb3c747ffe21dabd28c986e434071cd"
    os.environ["GOOGLE_CLOUD_PROJECT"] = "biller-switching-tls"
elif deploymentTarget == "cloud-dev":
    DOTENV_FILE = "./secrets/.env"
    load_dotenv(DOTENV_FILE)
    hexKey = os.environ["HEX_KEY"]
    ivHex = os.environ["IV_KEY"]
    
    # hexKey = os.getenv("HEX_KEY", "")
    # ivHex = os.getenv("IV_HEX", "")
    project_id = "lokapay-reseller-tmis"
    encryptedPrivateKeyHex = "e60c772a65b703dc4bd789a95ccc85278e5745d2b3ac907ce5bb48b492e9de30ea4e1f8fd770753e9def6c285212249de9c048af8290e446c75b6e191782d062292c36fb90155d450010e9be7e68f97001052543ad2c63b260e097e230d250145fef90a51abf5ff80a2d0309524d529e5a4ecc232279a8e5f96e3b8115a9e807"
    os.environ["GOOGLE_CLOUD_PROJECT"] = "lokapay-reseller-tmis"
else:
    DOTENV_FILE = ".env-prod"
    load_dotenv(DOTENV_FILE)
    hexKey = os.environ["HEX_KEY"]
    ivHex = os.environ["IV_KEY"]
    project_id = "production-"
    encryptedPrivateKeyHex = "-put signature here"
    os.environ["GOOGLE_CLOUD_PROJECT"] = "lokapay-reseller-tmis"


def decryptAes(ciphertextHex: str) -> str:
    key = bytes.fromhex(hexKey)
    iv = bytes.fromhex(ivHex)
    ciphertext = bytes.fromhex(ciphertextHex)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = signature_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

if deploymentTarget == "local":
    credentials = service_account.Credentials.from_service_account_file("sa-rsl-dev.json")
elif deploymentTarget == "cloud-dev":
    serviceAccountEnc = "0c32642bfac49370504bed74b9b017d6aab771fd3614c4c77f8b0e8673ed3a4205bedebd20b24d776cc4fa664e323a9dbdaa874ffea93865aeacb9dde99b032d791b96a3b491a8bff98f3b1aefb595f623321eca90472682f228aaa6be6d96d623451459f3e968d44c8b1ae4806606545306f01838e947c7f7c67082a3bb27bce7d76fe0d04d40ac31ba13ed178c34023ec888bd8630d21e0576ea199e4c8dbfb2476367870d0f71dc6e1ae74d7dcff55445eeca5bc6713ef04de248e042013a77af564a682d315630b29b7d000034c7d6e90698d88a084a87e9983ef96d1d39403cb1fc9c8d07ce89910e36fc6e48b5c14361bbf646fa2e1d9b469457c8e2e5f8e3bd7e2f46f9632f31e8fb144441a42e37a1ee1fddd3751a3af0de009fefd1b549a626244523fd59b58979a265944a12516d7b2d718752118f46984a7e2020af32a89e1aaadd85429a0924e3edaf61be0c757db42ffbef84abd24694415604b3a021f7ce49bb709c71e47639c9d06eea327d7e1014c3bfb85fe361c8781bda56bcf191174639df947222ffbcbe22d69f8126c0e3081d0eb198163ead2e968b5bbd96b31355c6a10a69817cb4e5821aa897aa309ec699a5bac0f7d26e516256bdf2239f029f02168faac54b0bc9a01220dc735373048c518f886ef64fdc63bbf4782d2965793f30d37edf9bbd8579db20ece1d9406e12ab116e08a028eb854c05d32d1203ad745d763a80398eaaca3247edb7f5cb58d51d5d6d20548d200f6db27fe4624b0ba48e7a7ec405fa6c221c97c1b16724fb1169918fa0c7fe36b935146948c523e4612bf5e9146510b9ac52cdbae4a0e0eb0ab7d49c667cc3448bbcf9af662303c687b2e730b3e00769751545235c743799465c3bf0c306b5aa8bc41a3d1d662e6b1b4af24a899ea6e77ba9eb8d61c89ef75005241271990a06d54b611daadae7f93f3e11876a6c0a4bf01fdf2a3d0bd37c11cd73994603f933c20ce4a24fe935117b195e467b59142e4a60768b0691f172d9704f0b6a7911c7fa642e023ef562a7dc4214eda6dcf4dd17b7c1e232f78c627df71fb07cb0c9b75ea5f01d24c7e9a31e2c1ffe3fed2cd111e8298481898a21aab7eda3809ba4da5bc3874956425ca43cdec5d921c16daea57a3ec230b4600dbef86044bc2c77d569f89966aa3088f7782f7a6e0749cc8261224d007a5c98f2f613d8f31ed1ecd20a83e4438669ec2e7977698eff69ed261e339bd122ef43a543e8a566ca9f67e199dca7750816b955aa32da0e91e9f16cf514f675b939b55b1c5f5ca3d7799df544178a5c23a4a83af8e8c414973121e4a5268760f2ca450ea122ee1cc9a01545b7955efd9356e7077dd068b99356ae1ff015424a516fb88fd84a11c6f09e46b3dbc5074f8ed32428efd27c1e4866e9d06adf8331feec3069ea3268818b57b69e8cab7106dd170caf6cdd12e023aa280cea0a75123003f6ad08dd4b507649fb52bdd60d13d97c80c2827b6e8c234d31e92c2adfa77b8d9bb92c7fdd73e8bd11da7784afa27a2fc9d95a5c848375f8a3dc3edf3b548daf59a28711d7d97c5ffb77b8f73070778f82f6a516829678f26ef0ecee8ba40faa8a921261b5ba899cac7bcf9b3cdce9d8e93675183c95440b256bd88922364dc47232858b74623b292d4141246741b64539436abedf27d7200756124238d4c13472e8fa86ca81fdc1231d289479dad6a7e877f9780bef7a1dbb9b1f4702baf6415e9605f7ba5123c6a4888f3f30d05c1172392af8029aa50e71ca70194c15beed6e6d4dac2ed7eb89c5decbee8e3849a4294ec97a2511b5a7af5a7daab8f45fe907c02836abccacaa05c6de8a04a955cbff28d663401ab0a154fb2de2e896da635cae228a2fc7ead7dfb2f61e5eb7093fca9d82bc7e8358434b4c87c8a1f8cb4f8a0908fff86bfc78dd295317268bbe2a9e512736e8b46ccdec6ba46c9fe543a7e3f322cde8655851c1ec4414ffeb97b1d55bf1ace5761dc13d8d567e394ac030d9e0ea2087868bd4314b0421c6684519e6f6236ce1bb68e391b8f62907d0b3b766efe7a91a68032e056fd517ce832dffcec7e16ddaf4786081a0d278251e20d814b2e4603e37a3f1b2ac8e44bd948aef8f510cde776e57dcbb8a9f40ba7a08a339826cc3bfdddf2d65b0a2fb79aa9816d825f616dc2c7eb4e6d142affecd74adcb208781704c149444bc50d4673347499447502b4089f868d6ef0b5b7ec82c0e92b83ec97275769cdad6a889b1dc560533b4d26e03d4a43bd4c6d7f013a232ebc4b2e34deccde0e5b79e319c2730808576b871adb43e0685d8ef0697e797a14aa7091e8faf6b8fdcc1c04fd264d0ca28b7eb1e6173e5b5ac8b106e38160ab2273627573887fcb88a46f9d68b3247acbb8b11d417fca993a3968800c6a52487ac185c0157c5e6ab0d0a49ee3f2ca511b5bb3be121ccb5f9a146d412a333cb8d799142807cfa30ef1253dfbb835306fc6f0e783eb974d22668aa6a50f03b70e0ab66a81bb9a78bb2de8c830fbb32dd612c51c2e7b2e7edc97a6a998cf2d6211702eafdb41daf396f16b6ab7d8a56c6d3b086744051ca1f8285bcc4b785c3ec201dc18d533339ecc05333d73d3301141ac04dee6e7f0ced03e8c24f73e9337e042d84586c55250183a0427f463f0fd16767cd238c6148a901a31e528b780f2573e8e1c0a2fae0051539c9aab1883222640832b16774c5817e56bd19fa23f2c5775120f337c924cfc2b1318c1f7418a28647a95c774856990057f05b581e76f8c22dfab040924a3846475a4a293cb8cc9a83bf2ce0ef14fc00c5c54207b54e68051a615443bb0a9a90f6b2486b324eebecec6595f59515808715a9983bea89be640b016fa2e030179f331a5ddabd7fc73cfe35a6541fcf8b3977b3a07f443dbbd06769b6787e5b53a183937060711287d5f46b4841f79a50c9b80309786b0cbcda87d146bcb9562f582c054bf54d0f810fca335ef1c9bf0f98f21a148c5a4dc6686735698dfabbfd93c6fe122a9a03bef526f100f7fd0802adc6d7f0135c37f2172e52049f89cb9bc1a8bdaed2bedddff447dbb703aa1ce2137656e872a505cb2c6026fa5caec0692491e2eb6767965d7de3f18232f8de8aa7ac22eb687297b848c3bf161c4d059429e0b578e0dc452d08b7b2b1f83ade0671c1784f2862a5758e08041bb2ec828395dbdd6d800f1e0bdfbe236a84e61efd577ef8ee1fddce26a8551329a9d89e429daff84af11098e4b30d801c25d52884e43c781015a9e87c1dd65cecab84df40c9188113b322b3e1081165c4c9c06666d648a4f46be691f4e04c777b11b1c88f4c272138fadc"
    decryptedSA = decryptAes(serviceAccountEnc)
    saDictionary = json.loads(decryptedSA)
    credentials = service_account.Credentials.from_service_account_info(saDictionary)
else:
    credentials = service_account.Credentials.from_service_account_file("sa-rsl-prod.json")


publisher = pubsub_v1.PublisherClient(
    credentials=credentials,
    publisher_options=pubsub_v1.types.PublisherOptions(enable_message_ordering=True),
)


def publishToPubsub(jsonTobeSent: Dict[str, Any], topic: str, orderingKey: Optional[str] = None):
    topic_path = publisher.topic_path(project_id, topic)
    data = json.dumps(jsonTobeSent).encode("utf-8")
    future = publisher.publish(
        topic_path,
        data,
        origin="transactionRequestRslPdam",
        username="system",
        ordering_key=orderingKey,
    )
    return future.result()


def signEd25519(messageString: str) -> str:
    privateKey = decryptAes(encryptedPrivateKeyHex)
    pem_bytes = privateKey.encode("utf-8")
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    signature = private_key.sign(messageString.encode("utf-8"))
    return base58.b58encode(signature).decode()


def verifySignature(trxSignature: str, message: str) -> bool:
    signature = base58.b58decode(trxSignature)
    try:
        coreSystemPublicKeyEd25519.verify(signature, message.encode())
        return True
    except InvalidSignature:
        return False


def getRandomNo() -> str:
    time_epoch = str(time.time_ns()).replace(".", "")
    seed = "".join(random.choices(string.ascii_letters + string.digits, k=7))
    return str(seed) + str(time_epoch[10:16])


class CartPdam(BaseModel):
    customerNumber: str
    product: str
    billerCode: str
    productCategory: str = "PDAM"
    qty: int = 1
    billAmount: int
    usedPromoId: Optional[str] = None


class Location(BaseModel):
    latitude: float
    longitude: float


class TransactionRequestPdam(BaseModel):
    userid: str
    signupDate: datetime
    deviceId: str
    appTrxId: str
    location: Optional[Location] = None
    trxDatetime: datetime
    promoCode: Optional[str] = None
    pinAuthorization: str
    paymentChannel: str
    usePoinFlag: bool
    cart: CartPdam
    fcmId: str
    appSignature: str


r = redis.Redis(host="10.229.181.43", port=6379, db=0, decode_responses=True)

try:
    response = r.ping()
    if response:
        print("Connected to Redis server.")
    else:
        print("Ping failed, no response from Redis server.")
except redis.ConnectionError:
    print("Failed to connect to Redis server.")
except Exception as e:
    print(f"An error occurred: {e}")


PIN_MAX_ATTEMPTS = 5
PIN_LOCKOUT_SECONDS = 900
USER_LOCK_TTL_SECONDS = 35

PROMO_BOOKING_BASE_URL = decryptAes(os.getenv("PROMO_BOOKING_BASE_URL")).rstrip("/")
PROMO_CONFIRM_BASE_URL = decryptAes(os.getenv("PROMO_CONFIRM_BASE_URL")).rstrip("/")
PROMO_ENGINE_TIMEOUT_SEC = int(decryptAes(os.getenv("PROMO_ENGINE_TIMEOUT_SEC")) or "8")

SECRET_KEY = decryptAes(os.getenv("SECRET_KEY_JWT")) or ""
ALGORITHM = decryptAes(os.getenv("ALGORITHM")) or ""
PASSKEY = decryptAes(os.getenv("PASSKEY")) or ""


def checkMaxLoginAttempt(redis_conn, userid: str) -> bool:
    key = f"pin_attempts:{userid}"
    attempts = redis_conn.get(key)
    if attempts and int(attempts) >= PIN_MAX_ATTEMPTS:
        return False
    return True


def incrementLoginAttempt(redis_conn, userid: str):
    key = f"pin_attempts:{userid}"
    attempts = redis_conn.get(key)
    if attempts:
        redis_conn.incr(key)
    else:
        redis_conn.set(key, 1, ex=PIN_LOCKOUT_SECONDS)


def checkDuplicateTrxId(redis_conn, appTrxId: str, params: TransactionRequestPdam, systemTrxId: str) -> bool:
    key = f"resellerTodayHistory:{appTrxId}"
    ttl = 86400

    trxData = {
        "systemTrxId": systemTrxId,
        "appTrxId": appTrxId,
        "trxDatetime": params.trxDatetime.isoformat(),
        "userid": params.userid,
        "deviceId": params.deviceId,
        "trxResult": "pending",
    }

    flat_data = []
    for k, v in trxData.items():
        flat_data.extend([k, json.dumps(v)])

    lua_script = """
    if redis.call('EXISTS', KEYS[1]) == 1 then
        return 0
    else
        redis.call('HMSET', KEYS[1], unpack(ARGV, 1, #ARGV - 1))
        redis.call('EXPIRE', KEYS[1], tonumber(ARGV[#ARGV]))
        return 1
    end
    """

    result = redis_conn.eval(lua_script, 1, key, *flat_data, ttl)
    return result == 0


def tryToAcquireRedisLock(userId: str):
    redisLockToken = str(uuid.uuid4())
    redisLockKey = f"lock:user:{userId}"
    lockResult = r.set(redisLockKey, redisLockToken, nx=True, ex=USER_LOCK_TTL_SECONDS)
    return bool(lockResult), redisLockToken


def releaseLock(lock_key: str, lock_value: str):
    script = """
    if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
    else
        return 0
    end
    """
    return r.eval(script, 1, lock_key, lock_value)


def acquireLockBlocking(userId: str, retry_interval=0.1, timeout=10):
    start_time = time.time()
    while True:
        lockResult, lockToken = tryToAcquireRedisLock(userId)
        if lockResult:
            return lockToken
        if time.time() - start_time > timeout:
            return False
        time.sleep(retry_interval)


def triggerLockRelease(userid: str, redisLockToken: Optional[str]):
    if not redisLockToken:
        return 0
    redisLockKey = f"lock:user:{userid}"
    return releaseLock(redisLockKey, redisLockToken)


def get_total_markup_for_child(child_id: str) -> Tuple[int, Optional[str]]:
    if r is None:
        return 0, None

    key = f"resellerMarkup:{child_id}"
    try:
        raw = r.hgetall(key)
        total = 0
        parent_id = None

        for _, json_str in raw.items():
            try:
                data = json.loads(json_str)
                if parent_id is None:
                    parent_id = data.get("parentId")

                if (data.get("type") or "").upper() == "FIXED":
                    total += int(data.get("value") or 0)
            except Exception:
                continue

        return total, parent_id
    except Exception as e:
        print("[get_total_markup_for_child] error:", e)
        return 0, None


def promo_engine_booking(
    transactionId: str,
    promoCode: str,
    resellerId: str,
    baseAmount: int,
    productId: str,
    paymentMethodId: str,
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    if not PROMO_BOOKING_BASE_URL:
        return False, {}, "PROMO_BOOKING_BASE_URL not set"

    payloadToken = {
        "service": "test-client",
        "role": "internal",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        "key": PASSKEY,
    }
    token = jwt.encode(payloadToken, SECRET_KEY, algorithm=ALGORITHM)

    url = f"{PROMO_BOOKING_BASE_URL}/promo/book"
    payload = {
        "txId": transactionId,
        "promoCode": promoCode,
        "resellerId": resellerId,
        "channel": "lokapay",
        "context": "PURCHASE_PDAM",
        "amount": int(baseAmount),
        "productId": productId,
        "paymentMethodId": paymentMethodId,
        "ttlSeconds": 900,
    }

    print(f"[PROMO][PDAM] BOOK payload={payload}", flush=True)

    headers = {
        "access_token": token,
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            url, json=payload, headers=headers, timeout=PROMO_ENGINE_TIMEOUT_SEC
        )
        ok_http = 200 <= resp.status_code < 300

        try:
            raw = resp.json()
        except Exception:
            raw = {"raw": resp.text}

        if not ok_http:
            return False, raw, f"BOOKING_HTTP_{resp.status_code}"

        if not bool(raw.get("success", False)):
            return False, raw, raw.get("message") or "BOOKING_NOT_OK"

        d = raw.get("data") or {}
        reward = d.get("reward") or {}

        reward_type = (reward.get("type") or "").upper().strip()
        free_product_id = (reward.get("freeProductId") or "").strip()

        reward_amount = 0
        rv = reward.get("value")
        try:
            if rv is not None and str(rv).strip() != "":
                reward_amount = int(float(str(rv)))
        except Exception:
            reward_amount = 0

        normalized = {
            "bookingId": (d.get("txId") or "").strip(),
            "promoId": (d.get("promoId") or "").strip(),
            "promoCode": (d.get("promoCode") or "").strip(),
            "ttlSeconds": int(d.get("ttlSeconds") or 0),
            "expiresAt": d.get("expiresAt"),
            "rewardType": reward_type,
            "rewardAmount": reward_amount,
            "rewardProductId": free_product_id,
            "raw": raw,
        }

        if not normalized["bookingId"] or not normalized["promoId"] or not normalized["rewardType"]:
            return False, raw, "BOOKING_BAD_RESPONSE"

        return True, normalized, None

    except Exception as e:
        return False, {}, f"BOOKING_EXCEPTION: {e}"


def promo_engine_cancel(
    transactionId: str,
    promoCode: str,
    resellerId: str,
    *,
    channel: str = "lokapay",
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    if not PROMO_BOOKING_BASE_URL:
        return False, {}, "PROMO_BOOKING_BASE_URL not set"

    payloadToken = {
        "service": "test-client",
        "role": "internal",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
        "key": PASSKEY,
    }
    token = jwt.encode(payloadToken, SECRET_KEY, algorithm=ALGORITHM)

    url = f"{PROMO_BOOKING_BASE_URL}/promo/cancel"
    payload = {
        "txId": transactionId,
        "promoCode": promoCode,
        "resellerId": resellerId,
        "channel": channel,
    }

    print(f"[PROMO][PDAM] CANCEL payload={payload}", flush=True)

    headers = {
        "access_token": token,
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            url, json=payload, headers=headers, timeout=PROMO_ENGINE_TIMEOUT_SEC
        )
        ok_http = 200 <= resp.status_code < 300

        try:
            raw = resp.json()
        except Exception:
            raw = {"raw": resp.text}

        if not ok_http:
            return False, raw, f"CANCEL_HTTP_{resp.status_code}"

        if not bool(raw.get("success", False)):
            return False, raw, raw.get("message") or "CANCEL_NOT_OK"

        d = raw.get("data") or {}
        normalized = {
            "success": True,
            "message": raw.get("message"),
            "promoId": d.get("promoId"),
            "promoCode": d.get("promoCode") or promoCode,
            "txId": d.get("txId") or transactionId,
            "raw": raw,
        }
        return True, normalized, None

    except Exception as e:
        return False, {}, f"CANCEL_EXCEPTION: {e}"


def processDeduction(
    userId: str,
    paymentAmount: int,
    pointsUseFlag: bool,
    redisLockToken: str,
    rewardAmt: int,
):
    print(
        f"[DED][PDAM] start userId={userId} paymentAmount={paymentAmount} pointsUseFlag={pointsUseFlag} rewardAmt={rewardAmt}",
        flush=True,
    )

    def getWalletInfo(user_id_prefix: str):
        keyIndex = f"userWalletInfo:{user_id_prefix}:list"
        walletIdListRaw = r.get(keyIndex)
        print("[wallet][PDAM] index_key =", keyIndex, "value =", walletIdListRaw, flush=True)

        if not walletIdListRaw:
            return []

        walletIdList = ast.literal_eval(walletIdListRaw)
        wallet_data_list = []

        for walletId in walletIdList:
            key = f"userWalletInfo:{user_id_prefix}:{walletId}"
            wallet_data = r.hgetall(key) or {}
            wallet_data["walletId"] = walletId
            wallet_data_list.append(wallet_data)

            print(
                f"[wallet][PDAM] {walletId} acctType={wallet_data.get('accountType')} "
                f"bal={wallet_data.get('walletBalance')} exp={wallet_data.get('expirationDate')}",
                flush=True,
            )

        return wallet_data_list

    def splitAndSortWallets(wallets):
        packages, loans, points, commission = [], [], [], []
        verificationResult = True

        for wallet in wallets:
            account_type = wallet.get("accountType")
            walletId = wallet.get("walletId")
            walletBalance = wallet.get("walletBalance")
            signature = wallet.get("signature")

            if walletId is None or walletBalance is None or signature is None:
                return False, packages, loans, points

            messageToBeVerified = f"{walletBalance}|{walletId}|{userId}"
            verificationResult = verifySignature(signature, messageToBeVerified)

            print(
                f"[SIG][PDAM] walletId={walletId} acctType={account_type} bal={walletBalance} verify={verificationResult}",
                flush=True,
            )

            if not verificationResult:
                print("FRAUD DETECTED !!!", flush=True)
                return False, packages, loans, points

            if account_type == "PACKAGE":
                packages.append(wallet)
            elif account_type == "LOAN":
                loans.append(wallet)
            elif account_type == "POINTS":
                points.append(wallet)
            else:
                commission.append(wallet)

        def sort_key(wallet):
            date_str = (wallet.get("expirationDate") or "").strip()
            try:
                return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return datetime.max

        packages.sort(key=sort_key)
        loans.sort(key=sort_key)
        points.sort(key=sort_key)

        return True, packages, loans, points

    def getPaymentSOF(packages, loans, points) -> List[Dict[str, Any]]:
        sourceOfFund = []
        remainingToBeDeducted = int(paymentAmount)
        paymentMappingIsFinished = False
        useLoanFlag = len(loans) > 0

        print(
            f"[SOF][PDAM] start remaining={remainingToBeDeducted} useLoanFlag={useLoanFlag} pointsUseFlag={pointsUseFlag}",
            flush=True,
        )

        if pointsUseFlag and len(points) > 0:
            pointsAmount = int(points[0].get("walletBalance") or 0)
            if pointsAmount >= remainingToBeDeducted:
                sourceOfFund.append(
                    {
                        "walletId": points[0].get("walletId"),
                        "userId": userId,
                        "paymentAmount": remainingToBeDeducted,
                    }
                )
                remainingToBeDeducted = 0
                paymentMappingIsFinished = True
            else:
                sourceOfFund.append(
                    {
                        "walletId": points[0].get("walletId"),
                        "userId": userId,
                        "paymentAmount": pointsAmount,
                    }
                )
                remainingToBeDeducted -= pointsAmount

        if remainingToBeDeducted <= 0:
            return sourceOfFund

        if not useLoanFlag:
            totalBalance = sum(int(w.get("walletBalance") or 0) for w in packages)
            if totalBalance < remainingToBeDeducted:
                return False, "Not sufficient balance"

            for wallet in packages:
                if paymentMappingIsFinished:
                    break

                walletBalance = int(wallet.get("walletBalance") or 0)
                wid = wallet.get("walletId")

                if walletBalance >= remainingToBeDeducted:
                    sourceOfFund.append(
                        {"walletId": wid, "userId": userId, "paymentAmount": remainingToBeDeducted}
                    )
                    remainingToBeDeducted = 0
                    paymentMappingIsFinished = True
                else:
                    sourceOfFund.append(
                        {"walletId": wid, "userId": userId, "paymentAmount": walletBalance}
                    )
                    remainingToBeDeducted -= walletBalance

            return sourceOfFund

        loanBal = int(loans[0].get("walletBalance") or 0)
        if loanBal < remainingToBeDeducted:
            return False, "Balance is not sufficient"

        sourceOfFund.append(
            {
                "walletId": loans[0].get("walletId"),
                "userId": userId,
                "paymentAmount": remainingToBeDeducted,
            }
        )
        return sourceOfFund

    def updateRedisLua(sourceOfFundJsonList: List[str]):
        lua_script = """
            local wallet_updates = {}
            local results = {}

            for i, arg in ipairs(ARGV) do
                local ok, entry = pcall(cjson.decode, arg)
                if not ok then
                    return {err = "Invalid JSON at ARGV[" .. i .. "]: " .. arg}
                end

                if not entry.walletId or not entry.userId or not entry.paymentAmount then
                    return {err = "Missing fields in wallet entry at ARGV[" .. i .. "]"}
                end

                local key = "userWalletInfo:" .. entry.userId .. ":" .. entry.walletId

                local currentBalance = redis.call("HGET", key, "walletBalance")
                local currentBalanceSig = redis.call("HGET", key, "signature")
                if not currentBalance then
                    return {err = "Wallet not found: " .. key}
                end

                local balanceNum = tonumber(currentBalance)
                local paymentAmount = tonumber(entry.paymentAmount)

                if not balanceNum or not paymentAmount then
                    return {err = "Invalid numeric values in wallet: " .. key}
                end

                if balanceNum < paymentAmount then
                    return {err = "Insufficient balance in wallet: " .. key}
                end

                local newBalance = balanceNum - paymentAmount

                table.insert(wallet_updates, {
                    key = key,
                    walletId = entry.walletId,
                    prevBalance = balanceNum,
                    prevBalanceSig = currentBalanceSig,
                    newBalance = newBalance
                })
            end

            for _, update in ipairs(wallet_updates) do
                redis.call("HSET", update.key, "walletBalance", tostring(update.newBalance))
                table.insert(results, {
                    walletId = update.walletId,
                    prevBalance = tostring(update.prevBalance),
                    newBalance = tostring(update.newBalance),
                    prevBalanceSig = tostring(update.prevBalanceSig)
                })
            end

            local time = redis.call("TIME")
            local sequenceHead = tonumber(time[1])
            local sequenceId = tonumber(time[2])

            return { "OK", tostring(sequenceHead), tostring(sequenceId), cjson.encode(results)}
        """
        return r.eval(lua_script, 0, *sourceOfFundJsonList)

    def updateSignature(dataToBeUpdated):
        lua_script = """
            local updateList = cjson.decode(ARGV[1])

            for i = 1, #updateList do
                local item = updateList[i]
                local userId = item["userId"]
                local walletId = item["walletId"]
                local incomingSequenceHead = tonumber(item["sequenceHead"])
                local incomingSequenceId = tonumber(item["sequenceId"])
                local incomingSignature = item["signature"]

                local redisKey = "userWalletInfo:" .. userId .. ":" .. walletId
                local currentSequenceHead = tonumber(redis.call("HGET", redisKey, "sequenceHead") or "0")

                if incomingSequenceHead < currentSequenceHead then
                    return "ERR"
                elseif incomingSequenceHead == currentSequenceHead then
                    local currentSequenceId = tonumber(redis.call("HGET", redisKey, "sequenceId") or "0")
                    if incomingSequenceId > currentSequenceId then
                        redis.call("HSET", redisKey,
                            "signature", incomingSignature,
                            "sequenceHead", incomingSequenceHead,
                            "sequenceId", incomingSequenceId
                        )
                    else
                        return "ERR"
                    end
                else
                    redis.call("HSET", redisKey,
                        "signature", incomingSignature,
                        "sequenceHead", incomingSequenceHead,
                        "sequenceId", incomingSequenceId
                    )
                end
            end

            return "OK"
        """
        updateListStr = json.dumps(dataToBeUpdated)
        return r.eval(lua_script, 0, updateListStr)

    wallets = getWalletInfo(userId)
    verificationResult, packages, loans, points = splitAndSortWallets(wallets)

    if verificationResult is False:
        return "ERR|Signature verification failed", False, [], [], [], [], []

    sourceOfFund = getPaymentSOF(packages, loans, points)

    if sourceOfFund is False:
        return "ERR|Failed to get source of fund", False, [], [], [], [], []

    if isinstance(sourceOfFund, tuple):
        if len(sourceOfFund) >= 2 and sourceOfFund[0] is False:
            return f"ERR|{sourceOfFund[1]}", False, [], [], [], [], []
        return "ERR|Failed to get source of fund", False, [], [], [], [], []

    toBeDeductedList = []
    for sof in sourceOfFund:
        toBeDeducted = int(sof.get("paymentAmount") or 0)
        if toBeDeducted > 0:
            toBeDeductedList.append(sof)

    wallet_args = [json.dumps(w) for w in toBeDeductedList]
    for i, arg in enumerate(wallet_args, 1):
        print(f"[DED][PDAM] ARGV[{i}]={arg}", flush=True)

    try:
        res, sequenceHead, sequenceId, listNewBalance = updateRedisLua(wallet_args)
    except Exception as e:
        return f"ERR|Redis deduction failed: {e}", False, [], [], [], [], []

    listNewBalance = json.loads(listNewBalance)

    updateList = []
    newWalletInfo = []
    for toBeUpdated in listNewBalance:
        toBeSigned = f"{toBeUpdated.get('newBalance')}|{toBeUpdated.get('walletId')}|{userId}"
        newSignature = signEd25519(toBeSigned)
        toBeUpdated["newBalanceSig"] = newSignature

        updateList.append(
            {
                "userId": userId,
                "walletId": toBeUpdated.get("walletId"),
                "expectedBalance": toBeUpdated.get("newBalance"),
                "sequenceHead": sequenceHead,
                "sequenceId": sequenceId,
                "signature": newSignature,
            }
        )
        newWalletInfo.append(
            {
                "walletId": toBeUpdated.get("walletId"),
                "currentBalance": toBeUpdated.get("newBalance"),
                "signature": newSignature,
            }
        )

    resultUpdateSignature = updateSignature(updateList)

    redisLockKey = f"lock:user:{userId}"
    releaseLock(redisLockKey, redisLockToken)

    if resultUpdateSignature != "OK":
        return "ERR|Failed to update wallet signature", False, [], [], [], [], []

    ptsCharge, walletCharge, loanCharge = [], [], []
    for chargingDetail in listNewBalance:
        wid = chargingDetail.get("walletId")
        amountToCharge = int(chargingDetail.get("prevBalance")) - int(chargingDetail.get("newBalance"))
        chargeInfo = {
            "amount": amountToCharge,
            "account_id": wid,
            "curr_bal": chargingDetail.get("newBalance"),
            "curr_sig": chargingDetail.get("newBalanceSig"),
            "prev_sig": chargingDetail.get("prevBalanceSig"),
        }

        if (wid or "").startswith("WP"):
            ptsCharge.append(chargeInfo)
        elif (wid or "").startswith("WD"):
            walletCharge.append(chargeInfo)
        else:
            loanCharge.append(chargeInfo)

    return "OK", True, ptsCharge, walletCharge, loanCharge, newWalletInfo, points


def sendInfoToGL(
    trxId,
    productId,
    chargeAmount,
    ptsCharge,
    walletCharge,
    loanCharge,
    paymentMethod,
    promoId,
    promoType,
    promoAmount,
    resellerId,
    billNo,
    parentId: Optional[str] = None,
    markup: int = 0,
):
    if promoType:
        promo = {
            "promo_id": promoId,
            "promo_type": promoType,
            "promo_amount": promoAmount,
        }
    else:
        promo = {}

    dataToBeSent = {
        "event": "RETAIL_TRANSACTION",
        "tx_id": trxId,
        "product": productId,
        "occurred_at": str(datetime.now()),
        "amount": chargeAmount,
        "deductions": {
            "points": ptsCharge,
            "cash": walletCharge,
            "loan": loanCharge,
        },
        "payment_method": paymentMethod,
        "promo": promo,
        "reseller_id": resellerId,
        "channel": "MOBILE",
        "bill_no": billNo,
        "commission": {
            "parent_id": parentId,
            "amount": markup,
        },
    }
    print(dataToBeSent, flush=True)
    return publishToPubsub(dataToBeSent, "retail-trx-gl-writer")


def get_firestore_client(serviceAccountEnc: str):
    global _firestore_client

    if _firestore_client is not None:
        try:
            list(_firestore_client.collections())
            return _firestore_client
        except Exception as e:
            print(f"Firestore client unhealthy, reinitializing: {e}")
            _firestore_client = None

    decryptedSA = decryptAes(serviceAccountEnc)
    sa_dict = json.loads(decryptedSA)
    creds = service_account.Credentials.from_service_account_info(sa_dict)

    _firestore_client = firestore.Client(
        credentials=creds,
        project=sa_dict["project_id"],
    )
    return _firestore_client


def recordInFirestore(userId: str, trxId: str, amount: int):
    try:
        serviceAccountEnc = "PASTE_FIRESTORE_SERVICE_ACCOUNT_ENC_SAME_AS_EXISTING_FILE"
        db = get_firestore_client(serviceAccountEnc)
        db.collection("userTransactions").document(userId).collection("transactions").document(trxId).set(
            {
                "amount": amount,
                "status": "PENDING",
            }
        )
    except Exception as e:
        print("!!!! ERROR PUBLISH TO FIRESTORE")
        print(e)


def sendLogPdam(
    systemTrxId,
    params,
    formattedDate,
    isPromoUsed,
    rewardAmount,
    paymentAmount,
    statusTrx,
    newWalletInfo,
    errDesc,
    promoBookingId: Optional[str] = None,
    promoEnginePromoId: Optional[str] = None,
    promoRewardType: Optional[str] = None,
    promoRewardAmount: int = 0,
    promoRewardProductId: Optional[str] = None,
    pointsWalletSnapshot: Optional[Dict[str, str]] = None,
):
    lat = float(getattr(getattr(params, "location", None), "latitude", 0.0) or 0.0)
    lon = float(getattr(getattr(params, "location", None), "longitude", 0.0) or 0.0)

    promo_used_flag = bool(isPromoUsed and promoBookingId and promoEnginePromoId and promoRewardType)

    walletInfo = list(newWalletInfo or [])

    if pointsWalletSnapshot and pointsWalletSnapshot.get("walletId"):
        exists = any(w.get("walletId") == pointsWalletSnapshot.get("walletId") for w in walletInfo)
        if not exists:
            walletInfo.append(pointsWalletSnapshot)

    constructDataHistory = {
        "transactionId": systemTrxId,
        "resellerId": params.userid,
        "createdBy": "backend",
        "createdOn": formattedDate or datetime.now(GMT_PLUS_7).isoformat(),
        "transactionDate": formattedDate or datetime.now(GMT_PLUS_7).isoformat(),
        "transactionEvent": "RETAIL_TRANSACTION",

        "isPromoUsed": promo_used_flag,
        "promoId": promoEnginePromoId if promo_used_flag else None,
        "promoAmount": int(promoRewardAmount or 0) if promo_used_flag else 0,
        "promoCode": params.promoCode if promo_used_flag else None,
        "promoType": promoRewardType if promo_used_flag else None,

        "paymentMethod": params.paymentChannel,
        "amount": int(paymentAmount or 0),
        "status": statusTrx,
        "billNo": params.cart.customerNumber,
        "productId": params.cart.product,
        "billerCode": params.cart.billerCode,
        "customerNumber": params.cart.customerNumber,
        "latitude": lat,
        "longitude": lon,
        "walletInfo": walletInfo,
        "errorDescription": errDesc or "",

        "promoBookingId": promoBookingId,
        "promoEnginePromoId": promoEnginePromoId,
        "promoRewardType": promoRewardType,
        "promoRewardAmount": int(promoRewardAmount or 0),
        "promoRewardProductId": promoRewardProductId,
        "usePoinFlag": bool(getattr(params, "usePoinFlag", False)),
    }

    publishToPubsub(constructDataHistory, "trx-to-sql-pdam", params.userid)


@app.post("/transactionRequestResellerPdam")
async def transactionRequestResellerPdam(params: TransactionRequestPdam):
    print(params, flush=True)
    veryStart = time.perf_counter()

    redisLockToken = None
    systemTrxId = None

    promo_booking_id = None
    promo_id = None
    reward_type = None
    reward_amount = 0
    reward_product_id = None

    try:
        systemTrxId = "TRX-" + getRandomNo()

        redisLockToken = acquireLockBlocking(params.userid, retry_interval=0.2, timeout=30)
        if not redisLockToken:
            formattedDate = datetime.now(GMT_PLUS_7).isoformat()
            sendLogPdam(
                systemTrxId,
                params,
                formattedDate,
                False,
                0,
                0,
                "ERR",
                [],
                "redis lock for user",
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "error",
                    "message": "Locking error",
                    "errorCode": "1031",
                },
            )

        resultCheck = checkMaxLoginAttempt(r, params.userid)
        if not resultCheck:
            triggerLockRelease(params.userid, redisLockToken)
            errMsg = "User PIN attempt exceeded, user is blocked"
            formattedDate = datetime.now(GMT_PLUS_7).isoformat()
            sendLogPdam(
                systemTrxId,
                params,
                formattedDate,
                False,
                0,
                0,
                "FAILED",
                [],
                errMsg,
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "error",
                    "message": errMsg,
                    "errorCode": "1021",
                },
            )

        billerCode = params.cart.billerCode
        productCategory = (params.cart.productCategory or "PDAM").upper()
        keyProduct = f"productDetail:{productCategory}:{billerCode}:{params.cart.product}"
        productInfo = r.hgetall(keyProduct) or {}
        if not productInfo:
            triggerLockRelease(params.userid, redisLockToken)
            errMsg = "Product config doesn't exist in redis"
            formattedDate = datetime.now(GMT_PLUS_7).isoformat()
            sendLogPdam(
                systemTrxId,
                params,
                formattedDate,
                False,
                0,
                0,
                "FAILED",
                [],
                errMsg,
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "error",
                    "message": errMsg,
                    "errorCode": "4091",
                },
            )

        isDuplicate = checkDuplicateTrxId(r, params.appTrxId, params, systemTrxId)
        if isDuplicate:
            triggerLockRelease(params.userid, redisLockToken)
            errMsg = "Duplicate app TrxId"
            formattedDate = datetime.now(GMT_PLUS_7).isoformat()
            sendLogPdam(
                systemTrxId,
                params,
                formattedDate,
                False,
                0,
                0,
                "FAILED",
                [],
                errMsg,
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "error",
                    "message": errMsg,
                    "errorCode": "1022",
                },
            )

        if params.paymentChannel not in ("DEPOSIT", "LOAN"):
            triggerLockRelease(params.userid, redisLockToken)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "error",
                    "message": f"Unsupported paymentChannel: {params.paymentChannel}",
                    "errorCode": "4092",
                },
            )

        markup, parentId = get_total_markup_for_child(params.userid)
        base_amount = int(params.cart.billAmount) + int(markup)

        promo_used = bool(params.promoCode and params.promoCode != "-")

        if promo_used:
            ok_bk, bk_data, bk_err = promo_engine_booking(
                transactionId=systemTrxId,
                promoCode=params.promoCode,
                resellerId=params.userid,
                baseAmount=base_amount,
                productId=params.cart.product,
                paymentMethodId=params.paymentChannel,
            )

            if ok_bk:
                promo_booking_id = (bk_data.get("bookingId") or "").strip()
                promo_id = (bk_data.get("promoId") or "").strip()
                reward_type = (bk_data.get("rewardType") or "").upper().strip()
                reward_amount = int(bk_data.get("rewardAmount") or 0)
                reward_product_id = (bk_data.get("rewardProductId") or "").strip()

                print(
                    f"[PROMO][PDAM] BOOKING_OK promoId={promo_id} bookingId={promo_booking_id} "
                    f"type={reward_type} amount={reward_amount} rewardProductId={reward_product_id}",
                    flush=True,
                )
            else:
                promo_used = False
                promo_booking_id = None
                promo_id = None
                reward_type = None
                reward_amount = 0
                reward_product_id = None

                print(
                    f"[PROMO][PDAM] BOOKING_SKIP promoCode={params.promoCode!r} err={bk_err} resp={bk_data}",
                    flush=True,
                )

        paymentAmount = base_amount
        if promo_used and reward_type == "DISCOUNT" and reward_amount > 0:
            paymentAmount = max(0, paymentAmount - reward_amount)

        print(
            f"[PAY][PDAM] base_amount={base_amount} paymentAmount={paymentAmount} "
            f"markup={markup} promo_used={promo_used} reward_type={reward_type} reward_amount={reward_amount}",
            flush=True,
        )

        (
            res,
            successFlag,
            ptsCharge,
            walletCharge,
            loanCharge,
            newWalletInfo,
            points,
        ) = processDeduction(
            params.userid,
            paymentAmount,
            params.usePoinFlag,
            redisLockToken,
            reward_amount,
        )

        pointsWalletSnapshot = None
        if reward_type == "CASHBACK" and points and len(points) > 0:
            pointsWalletSnapshot = {
                "walletId": points[0].get("walletId"),
                "currentBalance": str(points[0].get("walletBalance") or "0"),
                "signature": str(points[0].get("signature") or ""),
            }

        print(f"[PDAM] deduction result={res}", flush=True)
        print(f"[PDAM] ptsCharge={ptsCharge}", flush=True)
        print(f"[PDAM] walletCharge={walletCharge}", flush=True)
        print(f"[PDAM] loanCharge={loanCharge}", flush=True)

        if res != "OK":
            errMsg = "Failed in processing deduction wallet, loan, or points"
            if isinstance(res, str) and res.startswith("ERR|"):
                errMsg = res.split("|", 1)[1].strip() or errMsg

            try:
                triggerLockRelease(params.userid, redisLockToken)
            except Exception:
                pass

            formattedDate = datetime.now(GMT_PLUS_7).isoformat()
            sendLogPdam(
                systemTrxId,
                params,
                formattedDate,
                False,
                0,
                0,
                "FAILED",
                [],
                errMsg,
                promoBookingId=promo_booking_id,
                promoEnginePromoId=promo_id,
                promoRewardType=reward_type,
                promoRewardAmount=reward_amount,
                promoRewardProductId=reward_product_id,
                pointsWalletSnapshot=pointsWalletSnapshot,
            )

            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "FAILED",
                    "message": errMsg,
                    "transactionId": systemTrxId,
                },
            )

        formattedDate = datetime.now(GMT_PLUS_7).isoformat()

        sendLogPdam(
            systemTrxId,
            params,
            formattedDate,
            bool(promo_used and promo_booking_id),
            reward_amount,
            paymentAmount,
            "PENDING",
            newWalletInfo,
            "",
            promoBookingId=promo_booking_id,
            promoEnginePromoId=promo_id,
            promoRewardType=reward_type,
            promoRewardAmount=reward_amount,
            promoRewardProductId=reward_product_id,
            pointsWalletSnapshot=pointsWalletSnapshot,
        )

        glRes = sendInfoToGL(
            systemTrxId,
            params.cart.product,
            paymentAmount,
            ptsCharge,
            walletCharge,
            loanCharge,
            params.paymentChannel,
            promo_id or params.promoCode,
            reward_type,
            reward_amount,
            params.userid,
            params.cart.customerNumber,
            parentId,
            markup,
        )
        print(glRes, flush=True)

        recordInFirestore(params.userid, systemTrxId, paymentAmount)

        end = time.perf_counter()
        print(f"[PDAM] total elapsed = {((end - veryStart) * 1000):.2f} ms", flush=True)

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "OK",
                "message": "Transaction has been processed",
                "transactionId": systemTrxId,
            },
        )

    except Exception as e:
        try:
            if promo_booking_id and systemTrxId:
                ok_cc, cc_data, cc_err = promo_engine_cancel(
                    transactionId=systemTrxId,
                    promoCode=params.promoCode,
                    resellerId=params.userid,
                    channel="lokapay",
                )
                print(
                    f"[PROMO][PDAM] SAFETY_CANCEL ok={ok_cc} err={cc_err} resp={cc_data}",
                    flush=True,
                )
        except Exception:
            pass

        try:
            triggerLockRelease(params.userid, redisLockToken)
        except Exception:
            pass

        print(e, flush=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "ERROR",
                "message": str(e),
            },
        )