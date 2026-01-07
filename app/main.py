# pylint: disable=no-member, assignment-from-no-return
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime
from fastapi import FastAPI, status
import redis
import time
import string
import random
from datetime import datetime
import json
import ast
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as signature_padding
import base58
import os
from fastapi.responses import JSONResponse
import uuid
from google.cloud import pubsub_v1
from google.oauth2 import service_account
import uvicorn
from google.cloud import firestore

print("DEBUG - CONTAINER IS STARTING....")
_firestore_client = None

with open("coreSystemPublicKeyEd25519.pem", "rb") as f:
    coreSystemPublicKeyEd25519 = serialization.load_pem_public_key(f.read())

deploymentTarget = "cloud-dev"

if deploymentTarget == "local":
    DOTENV_FILE = '.env-dev'
    hexKey = "d13bc2164d9bee84e54f8c8b56ea4fe79a777f0014120ff7182b076d6e6464f6"
    ivHex = "80d726ebc538cb6fefb270e4f66deade"
    project_id = "lokapay-reseller-tmis"
    encryptedPrivateKeyHex = "39b7e73a44715c814a645847504462bbf85897d5f12f1e64f47e3710c5d440cdde0ae35620bd1ca52671b5d11742702882029bb9c7bb2bcf0d72b86a0a2fc1058c89192be608febbbc56e9ea6044a53471dc4cf563c52513b833b8d357b220a2c4c18eff6d39b1ad0811e508c2151f1b4bb3c747ffe21dabd28c986e434071cd"
    os.environ["GOOGLE_CLOUD_PROJECT"] = "biller-switching-tls"
elif deploymentTarget== "cloud-dev":
    DOTENV_FILE = '/secrets/.env'
    hexKey = os.environ["HEX_KEY"]
    ivHex = os.environ["IV_KEY"]

    project_id = "lokapay-reseller-tmis"
    encryptedPrivateKeyHex = "e60c772a65b703dc4bd789a95ccc85278e5745d2b3ac907ce5bb48b492e9de30ea4e1f8fd770753e9def6c285212249de9c048af8290e446c75b6e191782d062292c36fb90155d450010e9be7e68f97001052543ad2c63b260e097e230d250145fef90a51abf5ff80a2d0309524d529e5a4ecc232279a8e5f96e3b8115a9e807"
    os.environ["GOOGLE_CLOUD_PROJECT"] = "lokapay-reseller-tmis"
else:
    DOTENV_FILE = '.env-prod'
    hexKey = os.environ["HEX_KEY"]
    ivHex = os.environ["IV_KEY"]
    project_id = "production-"
    encryptedPrivateKeyHex = "-put signature here"
    os.environ["GOOGLE_CLOUD_PROJECT"] = "lokapay-reseller-tmis"

def decryptAes(ciphertextHex):
    key = bytes.fromhex(hexKey)
    iv = bytes.fromhex(ivHex)
    ciphertext = bytes.fromhex(ciphertextHex)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = signature_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

if deploymentTarget == 'local':
    credentials = service_account.Credentials.from_service_account_file("sa-rsl-dev.json")

elif deploymentTarget == 'cloud-dev':
    serviceAccountEnc = '0c32642bfac49370504bed74b9b017d6aab771fd3614c4c77f8b0e8673ed3a4205bedebd20b24d776cc4fa664e323a9dbdaa874ffea93865aeacb9dde99b032d791b96a3b491a8bff98f3b1aefb595f623321eca90472682f228aaa6be6d96d623451459f3e968d44c8b1ae4806606545306f01838e947c7f7c67082a3bb27bce7d76fe0d04d40ac31ba13ed178c34023ec888bd8630d21e0576ea199e4c8dbfb2476367870d0f71dc6e1ae74d7dcff55445eeca5bc6713ef04de248e042013a77af564a682d315630b29b7d000034c7d6e90698d88a084a87e9983ef96d1d39403cb1fc9c8d07ce89910e36fc6e48b5c14361bbf646fa2e1d9b469457c8e2e5f8e3bd7e2f46f9632f31e8fb144441a42e37a1ee1fddd3751a3af0de009fefd1b549a626244523fd59b58979a265944a12516d7b2d718752118f46984a7e2020af32a89e1aaadd85429a0924e3edaf61be0c757db42ffbef84abd24694415604b3a021f7ce49bb709c71e47639c9d06eea327d7e1014c3bfb85fe361c8781bda56bcf191174639df947222ffbcbe22d69f8126c0e3081d0eb198163ead2e968b5bbd96b31355c6a10a69817cb4e5821aa897aa309ec699a5bac0f7d26e516256bdf2239f029f02168faac54b0bc9a01220dc735373048c518f886ef64fdc63bbf4782d2965793f30d37edf9bbd8579db20ece1d9406e12ab116e08a028eb854c05d32d1203ad745d763a80398eaaca3247edb7f5cb58d51d5d6d20548d200f6db27fe4624b0ba48e7a7ec405fa6c221c97c1b16724fb1169918fa0c7fe36b935146948c523e4612bf5e9146510b9ac52cdbae4a0e0eb0ab7d49c667cc3448bbcf9af662303c687b2e730b3e00769751545235c743799465c3bf0c306b5aa8bc41a3d1d662e6b1b4af24a899ea6e77ba9eb8d61c89ef75005241271990a06d54b611daadae7f93f3e11876a6c0a4bf01fdf2a3d0bd37c11cd73994603f933c20ce4a24fe935117b195e467b59142e4a60768b0691f172d9704f0b6a7911c7fa642e023ef562a7dc4214eda6dcf4dd17b7c1e232f78c627df71fb07cb0c9b75ea5f01d24c7e9a31e2c1ffe3fed2cd111e8298481898a21aab7eda3809ba4da5bc3874956425ca43cdec5d921c16daea57a3ec230b4600dbef86044bc2c77d569f89966aa3088f7782f7a6e0749cc8261224d007a5c98f2f613d8f31ed1ecd20a83e4438669ec2e7977698eff69ed261e339bd122ef43a543e8a566ca9f67e199dca7750816b955aa32da0e91e9f16cf514f675b939b55b1c5f5ca3d7799df544178a5c23a4a83af8e8c414973121e4a5268760f2ca450ea122ee1cc9a01545b7955efd9356e7077dd068b99356ae1ff015424a516fb88fd84a11c6f09e46b3dbc5074f8ed32428efd27c1e4866e9d06adf8331feec3069ea3268818b57b69e8cab7106dd170caf6cdd12e023aa280cea0a75123003f6ad08dd4b507649fb52bdd60d13d97c80c2827b6e8c234d31e92c2adfa77b8d9bb92c7fdd73e8bd11da7784afa27a2fc9d95a5c848375f8a3dc3edf3b548daf59a28711d7d97c5ffb77b8f73070778f82f6a516829678f26ef0ecee8ba40faa8a921261b5ba899cac7bcf9b3cdce9d8e93675183c95440b256bd88922364dc47232858b74623b292d4141246741b64539436abedf27d7200756124238d4c13472e8fa86ca81fdc1231d289479dad6a7e877f9780bef7a1dbb9b1f4702baf6415e9605f7ba5123c6a4888f3f30d05c1172392af8029aa50e71ca70194c15beed6e6d4dac2ed7eb89c5decbee8e3849a4294ec97a2511b5a7af5a7daab8f45fe907c02836abccacaa05c6de8a04a955cbff28d663401ab0a154fb2de2e896da635cae228a2fc7ead7dfb2f61e5eb7093fca9d82bc7e8358434b4c87c8a1f8cb4f8a0908fff86bfc78dd295317268bbe2a9e512736e8b46ccdec6ba46c9fe543a7e3f322cde8655851c1ec4414ffeb97b1d55bf1ace5761dc13d8d567e394ac030d9e0ea2087868bd4314b0421c6684519e6f6236ce1bb68e391b8f62907d0b3b766efe7a91a68032e056fd517ce832dffcec7e16ddaf4786081a0d278251e20d814b2e4603e37a3f1b2ac8e44bd948aef8f510cde776e57dcbb8a9f40ba7a08a339826cc3bfdddf2d65b0a2fb79aa9816d825f616dc2c7eb4e6d142affecd74adcb208781704c149444bc50d4673347499447502b4089f868d6ef0b5b7ec82c0e92b83ec97275769cdad6a889b1dc560533b4d26e03d4a43bd4c6d7f013a232ebc4b2e34deccde0e5b79e319c2730808576b871adb43e0685d8ef0697e797a14aa7091e8faf6b8fdcc1c04fd264d0ca28b7eb1e6173e5b5ac8b106e38160ab2273627573887fcb88a46f9d68b3247acbb8b11d417fca993a3968800c6a52487ac185c0157c5e6ab0d0a49ee3f2ca511b5bb3be121ccb5f9a146d412a333cb8d799142807cfa30ef1253dfbb835306fc6f0e783eb974d22668aa6a50f03b70e0ab66a81bb9a78bb2de8c830fbb32dd612c51c2e7b2e7edc97a6a998cf2d6211702eafdb41daf396f16b6ab7d8a56c6d3b086744051ca1f8285bcc4b785c3ec201dc18d533339ecc05333d73d3301141ac04dee6e7f0ced03e8c24f73e9337e042d84586c55250183a0427f463f0fd16767cd238c6148a901a31e528b780f2573e8e1c0a2fae0051539c9aab1883222640832b16774c5817e56bd19fa23f2c5775120f337c924cfc2b1318c1f7418a28647a95c774856990057f05b581e76f8c22dfab040924a3846475a4a293cb8cc9a83bf2ce0ef14fc00c5c54207b54e68051a615443bb0a9a90f6b2486b324eebecec6595f59515808715a9983bea89be640b016fa2e030179f331a5ddabd7fc73cfe35a6541fcf8b3977b3a07f443dbbd06769b6787e5b53a183937060711287d5f46b4841f79a50c9b80309786b0cbcda87d146bcb9562f582c054bf54d0f810fca335ef1c9bf0f98f21a148c5a4dc6686735698dfabbfd93c6fe122a9a03bef526f100f7fd0802adc6d7f0135c37f2172e52049f89cb9bc1a8bdaed2bedddff447dbb703aa1ce2137656e872a505cb2c6026fa5caec0692491e2eb6767965d7de3f18232f8de8aa7ac22eb687297b848c3bf161c4d059429e0b578e0dc452d08b7b2b1f83ade0671c1784f2862a5758e08041bb2ec828395dbdd6d800f1e0bdfbe236a84e61efd577ef8ee1fddce26a8551329a9d89e429daff84af11098e4b30d801c25d52884e43c781015a9e87c1dd65cecab84df40c9188113b322b3e1081165c4c9c06666d648a4f46be691f4e04c777b11b1c88f4c272138fadc'
    decryptedSA = decryptAes(serviceAccountEnc)
    saDictionary = json.loads(decryptedSA)
    credentials = service_account.Credentials.from_service_account_info(saDictionary)
    
else:
    credentials = service_account.Credentials.from_service_account_file("sa-rsl-prod.json")

publisher = pubsub_v1.PublisherClient(credentials=credentials, 
            publisher_options=pubsub_v1.types.PublisherOptions(enable_message_ordering=True))

def publishToPubsub(jsonTobeSent, topic, orderingKey=None):
        topic_path = publisher.topic_path(project_id, topic)
        jsonToBeSent = json.dumps(jsonTobeSent)
        data = jsonToBeSent.encode("utf-8")
        try:
            future = publisher.publish(
                topic_path, data, origin="transactionRequestRsl", username="system", ordering_key=orderingKey
            )
        except Exception as e:
            print(e)
        submissionId = future.result()
        return submissionId

def signEd25519(messageString):
    privateKey = decryptAes(encryptedPrivateKeyHex)
    pem_bytes = privateKey.encode('utf-8')

    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    message = messageString.encode('utf-8')

    signature = private_key.sign(message)
    b58Signature = base58.b58encode(signature).decode()
    return b58Signature

def verifySignature(trxSignature, message) -> bool: 
    signature = base58.b58decode(trxSignature)
    try:    
        coreSystemPublicKeyEd25519.verify(signature, message.encode())
        return True
    except InvalidSignature:
        return False
    
def getRandomNo():
    time_epoch = str(time.time_ns()).replace(".", "")
    seed = ''.join(random.choices(string.ascii_letters + string.digits, k=7))
    randomNo = str(seed) + str(time_epoch[10:16])
    return randomNo

app = FastAPI()

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
    location: Location
    trxDatetime: datetime
    promoCode: Optional[str] = None
    pinAuthorization: str
    paymentChannel: str
    usePoinFlag: bool
    cart: CartPdam
    fcmId: str
    appSignature: str

r = redis.Redis(host='10.229.181.43', port=6379, db=0, decode_responses=True)
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

def checkMaxLoginAttempt(redis_conn, userid):
    key = f"pin_attempts:{userid}"
    attempts = redis_conn.get(key)
    if attempts and int(attempts) >= PIN_MAX_ATTEMPTS:
        return False
    return True

def incrementLoginAttempt(redis_conn, userid):
    key = f"pin_attempts:{userid}"
    attempts = redis_conn.get(key)
    if attempts:
        redis_conn.incr(key)
    else:
        redis_conn.set(key, 1, ex=PIN_LOCKOUT_SECONDS)

def checkDuplicateTrxId(redis_conn, appTrxId, params, systemTrxId):
    key = f"resellerTodayHistory:{appTrxId}"
    ttl = 86400  # 24 hours

    trxData = {
        "systemTrxId": systemTrxId,
        "appTrxId": appTrxId,
        "trxDatetime": params.trxDatetime.isoformat(),
        "userid": params.userid,
        "deviceId": params.deviceId,
        "trxResult": "pending"
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

    return result == 0  # If 0, it's duplicate

def redeemPromoCodePdam(promoCode, params):
    key = f"promoReseller:{promoCode}"
    if r.exists(key):
        promoInfo = r.hgetall(key)
        targetAccountAgeDays = int(promoInfo.get('targetAccountAgeDays', 0))
        if targetAccountAgeDays == 0:
            targetAccountAgeDays = 10000000
        minTrxAmount = int(float(promoInfo.get('minTrxAmount', 0)))
        expirationDate = promoInfo.get('expirationDate', '1970-01-01 00 00:00')
        targetProduct = json.loads(promoInfo.get('targetProduct'))
        paymentMethod = json.loads(promoInfo.get('paymentMethod'))
        targetSellerId = json.loads(promoInfo.get('targetSellerId'))
        quotaPerUser = int(promoInfo.get('quotaPerUser', 0))
        allowedDailyUsage = int(promoInfo.get('dailyQuota', 0))
        discountAmount = int(float(promoInfo.get('discountAmount', 0)))
        rewardType = promoInfo.get('rewardType', 0)
        totalQuota = int(promoInfo.get('totalQuota', 0))

        if not promoInfo:
            return False, "Invalid promo code", 0

        accountAgeDays = (datetime.now() - params.signupDate).days
        if not accountAgeDays < targetAccountAgeDays:
            return False, "Account age does not meet promo requirements", discountAmount
        if params.paymentChannel not in paymentMethod and paymentMethod != ["ALL"]:
            return False, "Payment method not eligible for promo", discountAmount
        if params.cart.product not in targetProduct and targetProduct != ["ALL"]:
            return False, "Product not eligible for promo", discountAmount
        if targetSellerId != ["ALL"]:
            if params.userid not in targetSellerId:
                return False, "Seller not eligible for promo", discountAmount
            
        productPrice = int(params.cart.billAmount)
        if productPrice < minTrxAmount:
            return False, "Transaction amount does not meet promo requirements", discountAmount

        redeemAttemptResult = redeemPromoCodeLua(
            promoCode,
            datetime.now().strftime('%Y-%m-%d'),
            params.userid,
            allowedDailyUsage,
            quotaPerUser,
            totalQuota
        )
        if not redeemAttemptResult:
            return False, "Promo code usage limit exceeded", discountAmount
        return True, rewardType, discountAmount
    else:
        return False, "Promo code does not exist", 0

def redeemPromoCodeLua(promoCode, currentDate, userId, dailyLimit, userLimit, totalQuota):
    available_key = f"promoUsage:{promoCode}:totalPromo:availableToBeRedeemed"
    daily_key = f"promoUsage:{promoCode}:dailyUsage:{currentDate}"
    user_key = f"promoUsage:{promoCode}:userRedemption:{userId}"
    lua_script = """
    local available_key = KEYS[1]
    local daily_key = KEYS[2]
    local user_key = KEYS[3]

    local daily_limit = tonumber(ARGV[1])
    local user_limit = tonumber(ARGV[2])
    local total_quota = tonumber(ARGV[3])

    -- Get current values
    local available = tonumber(redis.call("GET", available_key))
    local daily_usage = tonumber(redis.call("GET", daily_key))
    local user_usage = tonumber(redis.call("GET", user_key))

    -- If the promo has never been redeemed before
    if available == nil then
        -- Initialize the available quota
        redis.call("SET", available_key, total_quota - 1)

        -- Initialize today's daily usage record
        redis.call("SET", daily_key, 1)

        -- Initialize user's usage record
        redis.call("SET", user_key, 1)

        return 1
    -- If there are no available promos left
    else
        if available <= 0 then
            return 0
        end
    end

    if daily_usage == nil then
        redis.call("SET", daily_key, 0)
        daily_usage = 0
    end
    -- Check if daily usage is below the daily limit
    if daily_usage < daily_limit then
        -- If user hasn't redeemed the promo yet, initialize user usage to 1
        if user_usage == nil then
            redis.call("SET", user_key, 0)

        else
        -- Check user usage limit
            if (user_usage + 1) > user_limit then
                return 0
            end
        end

        -- Perform atomic updates
        redis.call("DECR", available_key)  -- Decrease available quota
        redis.call("INCR", daily_key)     -- Increment today's daily usage
        redis.call("INCR", user_key)      -- Increment user's usage

        return 1
    else
        return 0
    end
    """

    result = r.eval(
        lua_script,
        3,
        available_key,
        daily_key,
        user_key,
        dailyLimit,
        userLimit,
        totalQuota
    )

    return result == 1

def processDeduction(userId, paymentAmount, pointsUseFlag, redisLockToken, rewardAmt):
    def getWalletInfo(user_id_prefix):
        keyIndex = f"userWalletInfo:{user_id_prefix}:list"
        walletIdList = r.get(keyIndex)
        print("[wallet] index_key =", keyIndex, "value =", walletIdList)
        walletIdList = ast.literal_eval(walletIdList)
        wallet_data_list = []
        for walletId in walletIdList:
            key = f"userWalletInfo:{user_id_prefix}:{walletId}"
            wallet_data = r.hgetall(key)
            print("[wallet] key =", key, "fields =", list(wallet_data.keys()))
            wallet_data_list.append(wallet_data)
        return wallet_data_list
    
    def splitAndSortWallets(wallets):
        packages = []
        loans = []
        points = []

        for wallet in wallets:
            account_type = wallet.get('accountType')
            print(f"Account Type : {account_type} ")
            walletId = wallet.get('walletId')
            print(f"walletId : {walletId} ")
            walletBalance = wallet.get('walletBalance')
            print(f"walletBalance : {walletBalance} ")
            signature = wallet.get('signature')
            print(f"signature : {signature} ")
            messageToBeVerified = walletBalance + "|" + walletId + "|" + userId
            print(f"Message to be verified : {messageToBeVerified}")
            verificationResult = verifySignature(signature, messageToBeVerified)
            if not verificationResult :
                print("FRAUD DETECTED !!!")
                return verificationResult, packages, loans, points
            # print(f"Verification Result : {walletId} - {verificationResult}")
            # print("-------")
            if account_type == "PACKAGE":
                packages.append(wallet)
            elif account_type == "LOAN":
                loans.append(wallet)
            else:
                points.append(wallet)

        def sort_key(wallet):
            date_str = wallet.get('expirationDate', '').strip()  # Remove extra spaces
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
        return verificationResult, packages, loans, points
    
    def getPaymentSOF(packages, loans, points)-> List[Dict[str, Any]]:
        sourceOfFund = []
        remainingToBeDeducted = paymentAmount
        payByPoints = 0
        payByWallet = 0
        paymentMappingIsFinished = False
        useLoanFlag = False
        
        if len(loans)==0:
            useLoanFlag = False
        else:
            useLoanFlag = True

        if pointsUseFlag and len(points)>0:
            pointsAmount = int(points[0].get('walletBalance'))
            if pointsAmount>=paymentAmount:
                remainingToBeDeducted = 0
                paymentMappingIsFinished = True
                appendWallet = {
                        "walletId": points[0].get('walletId'),
                        "userId": userId,
                        "paymentAmount": paymentAmount
                    }
                sourceOfFund.append(appendWallet)
            else:
                remainingToBeDeducted = paymentAmount - pointsAmount
                appendWallet = {
                        "walletId": points[0].get('walletId'),
                        "userId": userId,
                        "paymentAmount": pointsAmount
                    }
                sourceOfFund.append(appendWallet)
                
        if not useLoanFlag:
            totalBalance = 0
            for wallet in packages:
                totalBalance = totalBalance + int(wallet.get('walletBalance'))
            if totalBalance < remainingToBeDeducted:
                return False, "Not sufficient balance"
            for wallet in packages:
                if not paymentMappingIsFinished:
                    walletBalance = int(wallet.get('walletBalance'))
                    if walletBalance >= remainingToBeDeducted:
                        paymentMappingIsFinished = True
                        appendWallet =  {
                            "walletId": wallet.get('walletId'),
                            "userId": userId,
                            "paymentAmount": remainingToBeDeducted
                        }
                        remainingToBeDeducted = 0
                        sourceOfFund.append(appendWallet)
                    else:
                        remainingToBeDeducted = remainingToBeDeducted - walletBalance
                        appendWallet =  {
                            "walletId": wallet.get('walletId'),
                            "userId": userId,
                            "paymentAmount": walletBalance
                        }
                        sourceOfFund.append(appendWallet)
        else:
            totalBalance = int(loans[0].get('walletBalance'))
            if totalBalance<remainingToBeDeducted:
                return False, 'Balance is not sufficient'
            else:
                paymentMappingIsFinished = True
                loanBalance = int(loans[0].get('walletBalance'))
                appendWallet =  {
                    "walletId": loans[0].get('walletId'),
                    "userId": userId,
                    "paymentAmount": remainingToBeDeducted
                }
                sourceOfFund.append(appendWallet)
        return sourceOfFund
    
    def updateRedisLua(sourceOfFund):
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
                -- Store for update
                
                local newBalance = balanceNum - paymentAmount

                -- Save for update and later reporting
                table.insert(wallet_updates, {
                    key = key,
                    walletId = entry.walletId,
                    prevBalance = balanceNum,
                    prevBalanceSig = currentBalanceSig,
                    newBalance = newBalance
                })
            end

            -- Apply deductions
            for _, update in ipairs(wallet_updates) do
                redis.call("HSET", update.key, "walletBalance", tostring(update.newBalance))

                table.insert(results, {
                    walletId = update.walletId,
                    prevBalance = tostring(update.prevBalance),
                    newBalance = tostring(update.newBalance),
                    prevBalanceSig = tostring(update.prevBalanceSig)
                })
            end

            -- Get Redis server time (sequenceId)
            local time = redis.call("TIME")
            local sequenceHead = tonumber(time[1])
            local sequenceId = tonumber(time[2])

            -- Return status and sequenceId
            return { "OK", tostring(sequenceHead), tostring(sequenceId), cjson.encode(results)}
        """
        result = r.eval(lua_script, 0, *wallet_args)
        print(f"---> Update redis lua : {result}")
        return result
    
    def updateSignature(dataToBeUpdated):
        print(dataToBeUpdated)
        lua_script = """
            -- ARGV[1] is a JSON string representing updateList
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
        result = r.eval(lua_script, 0, updateListStr)
        print(result)
        return result

    wallets = getWalletInfo(userId)
    verificationResult, packages, loans, points = splitAndSortWallets(wallets)
    if verificationResult == False:
        return "ERR", True, [], [], []
    else:
        sourceOfFund = getPaymentSOF(packages, loans, points)
        toBeDeductedList = []
        for sof in sourceOfFund:
            toBeDeducted = sof.get('paymentAmount')
            if toBeDeducted>0:
                toBeDeductedList.append(sof)
        wallet_args = [json.dumps(w) for w in toBeDeductedList]

        for i, arg in enumerate(wallet_args, 1):
            print(f"ARGV[{i}]: {arg}")
        res, sequenceHead, sequenceId, listNewBalance = updateRedisLua(wallet_args)
        listNewBalance = json.loads(listNewBalance)
        updateList = []
        newWalletInfo = []
        for toBeUpdated in listNewBalance:
            toBeSigned = toBeUpdated.get('newBalance')+'|'+ toBeUpdated.get('walletId')+'|'+userId
            newSignature = signEd25519(toBeSigned)
            toBeUpdated["newBalanceSig"] = newSignature
            data = {
                "userId": userId,
                "walletId": toBeUpdated.get('walletId'),
                "expectedBalance": toBeUpdated.get('newBalance'),
                "sequenceHead": sequenceHead,
                "sequenceId": sequenceId,
                "signature": newSignature
            }
            newWalletUpdatedBalance = {
                "walletId": toBeUpdated.get('walletId'),
                "currentBalance": toBeUpdated.get('newBalance'),
                "signature": newSignature
            }
            newWalletInfo.append(newWalletUpdatedBalance)
            updateList.append(data)
        resultUpdateSignature = updateSignature(updateList)
        if resultUpdateSignature == "OK":
            redisLockKey = f"lock:user:{userId}"
            resRelease = releaseLock(redisLockKey, redisLockToken)
            print(f"Update signature and sequence is successful, lock is released : {resRelease}")
        else:
            print("Update fail")
            resRelease = releaseLock(redisLockKey, redisLockToken) # IN DEBUG MODE
        ptsCharge = []
        walletCharge = []
        loanCharge = []
        for chargingDetail in listNewBalance:
            ptsChargeWalletCheck = chargingDetail.get('walletId')
            amountToCharge = int(chargingDetail.get('prevBalance')) - int(chargingDetail.get('newBalance'))
            chargeInfo = {
                        "amount": amountToCharge,
                        "account_id": ptsChargeWalletCheck,
                        "curr_bal": chargingDetail.get('newBalance'),
                        "curr_sig": chargingDetail.get('newBalanceSig'),
                        "prev_sig": chargingDetail.get('prevBalanceSig')
                    }
            if ptsChargeWalletCheck[:2]=="WP":
                ptsCharge.append(chargeInfo)
            elif ptsChargeWalletCheck[:2]=="WD":
                walletCharge.append(chargeInfo)
            else:
                loanCharge.append(chargeInfo)
                
        return res, True, ptsCharge, walletCharge, loanCharge, newWalletInfo, points
    
# def verifyCurrentWalletSignature(params):
#     toBeVerified = {
#             "id": "A-xyz123abc456",
#             "createdOn": "2025-09-14T08:15:30Z",
#             "ownerId": "R-abc987xyz654",
#             "currentBalance": 125000.00,
#             "latestTransaction": "2025-09-14T09:20:15Z",
#             "latestTransactionId": "TH-20250914abcd1234",
#             "accountType": "PACKAGE"
#             }
    
def tryToAcquireRedisLock(userId):
    redisLockToken = str(uuid.uuid4())
    redisLockKey = f"lock:user:{userId}"
    lockResult = r.setnx(redisLockKey, redisLockToken)
    return lockResult, redisLockToken

def releaseLock(lock_key, lock_value):
    script = """
    if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
    else
        return 0
    end
    """
    res = r.eval(script, 1, lock_key, lock_value)
    return res

def acquireLockBlocking(userId, retry_interval=0.1, timeout=10):
    start_time = time.time()
    while True:
        lockResult, lockToken = tryToAcquireRedisLock(userId)
        if lockResult:
            return lockToken
        if time.time() - start_time > timeout:
            return False
        time.sleep(retry_interval) 

def sendInfoToGL(trxId, productId, chargeAmount, ptsCharge, walletCharge, loanCharge, paymentMethod, promoId, promoType, promoAmount, resellerId, billNo, parentId: Optional[str] = None, markup: int = 0):
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
                "loan": loanCharge
            },
            "payment_method": paymentMethod,
            "promo": promo,
            "reseller_id": resellerId,
            "channel": "MOBILE",
            "bill_no": billNo,
            "commission": {
                "parent_id": parentId,
                "amount": markup
            }
        }
        print(dataToBeSent)
        res = publishToPubsub(dataToBeSent, 'retail-trx-gl-writer')
        return res
    
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

def getProductPrice(productId, billerCode, productCategory):
    redisKey = f"productDetail:{billerCode}:{productCategory}:{productId}"
    productDetail = r.hgetall(redisKey)
    productPrice = int(productDetail.get('price'))
    if productPrice <= 1000:
        return False, -1
    else:
        return True, productPrice
    
def triggerLockRelease(userid, redisLockToken):
    redisLockKey = f"lock:user:{userid}"
    resRelease = releaseLock(redisLockKey, redisLockToken)
    return resRelease


def get_firestore_client(serviceAccountEnc):
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
    credentials = service_account.Credentials.from_service_account_info(sa_dict)
    _firestore_client = firestore.Client(
        credentials=credentials,
        project=sa_dict["project_id"]
    )
    return _firestore_client

def recordInFirestore(userId, trxId, amount):
    try:
        serviceAccountEnc="f92c13d37c4b0a7c6eb68f56335988ca1ec23418f83231746a0c72933f54f04053784651470723f9034067415142b0bf758bcf5339aa2811878538ddc8a1941dde4224bcebc0e85aed0b4346c1b1e7485b3abdb26053f652c6b86792b8d217ddd9c1042ef53ec46a74bbdb5d4b5d50dfb08d7dbbd945bb7c3700d71f4c13121862b66a048634e718ff9617add9184b449277d879c3b57c681f6ff1e004c573512232a6c02023ecab0bb37f3a40b26d1ce31ffe999d5712287e7aef82d3e569d8736fea674636c2979379099d83f4d83d83ade83bc39e2196823a52bf9afc904de5358787c95b935e175704ec894409142bdd40dbec87084c5d03c3e01bf762ebbc19f449ae3a55d72f39cc3a28f7d4e6197f8c0ad36e44d3274d1a0023e4681b184a248d70643c68fb506eb13a99c0c2eaa5d35c603f40f8c30073a08dd983890b70864eb2e30c3332f00c234919b39a476cafceda8b4f7aec184774db7cf322bfd1b4e6babc730b2c50675306b6abbf3e8b2838544cce9b01f60e7d1d0e4123bb28cf9e11a57697a16e77ce2d2b329db9fa32217f23c368eeb87c3a276d1c24c66f233c607b37de0c7faf14dc8d4cce4879ba6a66be884c812de11fc3ad7238a75b7163ae923c2932df0e9f823ff3eac5c8f6cdca0cc2c1a4a78b9d1e2f7f1eb47a1d003bd9d7e2be7582a84bd8339b4e623cb15ff25c3e28589e9cb6e5b355b46101c40b88761be40a6a3549377d90ea62f28e4ea95291bce7e98eaa8b8790c47a755ab06a2160870b6aeb0c3149e6e704ca380b2bfba437a03243ad5f15a9275b65636d96e5b9bf3e4fbcb24474c7856ae414f2b682d273570fea7390f40741ecbe17c3cc97c25e4ae469153d05d7cc5d77a42bdeca1d369d3137f66b0690be133f222df0e67ccb6475d1936e91f619c28c49bf66ab4d2d3d5823be97d511fa64bce93063886caf7a64979ec7d02218c5db2475ae9ad976245ad43be61345bf4a97a5590631242b6d019b3ac31c4e6b4e3a87405eaffe819bd2aabc957e765e541bb3577419cc92be1968ba1d9c46f844ca8347ad03d9b3a9d1999c7a44d9e3a4794fe31c9763a616d0ea16063e76d0ede2f1ffbea016f8ab84cba8c927d1db3ca6088ed06a0314f3b22ed816fe664c823d122fb147217f130088c1259cf0d062bdda3f252b8995b997893d90f72541b6c9d1b86371a89c6c38596e3031259c094093cbe2a0d10e0d5750ee233b088cfcd105db1a39e4b423b3251aee5016f91105481fa39b333b52ce82ffca26eba41e40477ddea08d8095a1afd935825c0f55fb7050ee969a34d40cea06b36d9434bb311eac7f02deec04bf9e5daae7d91e0f379823cc754fb0ce3ebb535d44bd647216edce19955738d1478269733a44a1fa04a1eeace71e7681614c9d85f039d50fc12d9e5218408a38db89d588eae19eb25956416195909d0f7641f89b2036d3d6f95c172377fa6715b9972de776aa15248263ca538e78bf59e08155e6b2b115098bc35a984ac0e7e7945377bcbc9250770c817f8d5163f6e719e97c34fac5b269fbcc7f8478ea6b5c8fea2504723de6c98789e2e6b8e5570a0f593f05a9321447fca4007cf27bb647a0dae658646e930e968299cedd9cbdb3a900afb960f82930d179a15734739800ad214cb6d1af966aabd31704cd778cb69cac3e823d0d9e99cd878e524dbee46721557c7c7eb48d05e86ffe1c0cc652ffb2b6fe9d0c2e70ed4846b56b6c4e3d07f0c35e870aaeeef77cc388a88897af6217621d46ed6240dc145734a3987031bda95a32492d7be060d9359004123d206fc6c11b8945e8e2a89af1c2ea54b83fad9d2586515cb9c24c9cfc797107fbb50a106673bc644cec38ee22e433009ba76136e9263b080d62ab699d4fe91ddb933e6937cba2716465dbcb0c900cf2c3ad260d1e8034e3f84069ad371b3a1d105d09d83976b54f1a44d2e60200ad9d6d09c0a8ee69fe1cf725186e0c153cb692d078a271ed2aceea893cbdf4f0f6fd7a4b53b45f042393542bd9b958a4fad583009b03f5a9368ce04a0bbd458c3656de96acc6fccefb6cdbb13a06f1037716c49a8fc635fd725127f557cf8d89c32bf4b73332a52bb67d45637a85d6a008bf0f77886dac51aac752f6afedb06238987e51c1d6a50c4f99f07e2565df51ee5c57be1bd3a77c4578a2a479b1f64e358eff6c3b7cfa95fe1ff83feb90eab77943631ef17aecdffb7b8325cd7673f2c1aaf0cd4c654ec3fda422269ed67fbe75d54c50de450ef5787610f5fd0f9c942acaa64a723a83f9e7b19cd552aa8a23e55977854088bf81cda15e15943e8fd9199ed36adeaedaf7da49af34e206a1421a59bd10227d77bdabfd410c1a88020ecb8d7fff7342b8d2e1853397afe0464a6b5c2dc45e003eb8e889815f98aa1f46b4197a4df3d40eef0f161cc58992bca1ed2efaa97bca10bfb5fbeb1aeee067197cbb3c8bc5a5507ce83cb0c8e0360487b7136d920bb62fc0c4f5a38ff642691822a180e7c6f7e63615c6d782c7beaf04ba73a18865ad106f99e92f17a0db0f94034e9cae18e5ab438889e42762b63462d367477693bf10a5546e8333f4e4d5223687e65addc715b63aa325cfd4dafcf5adcdb7945c2a8b87183164deaa49231fafec75df54f7799598f0341506607ff8071c284331d086c638e267e97a051029034d1c65e9b829a7b55eda5a525b3c55dcfe5a5b348138ca6517f5dba9f9581abca00a2da7d09c251d36f6882d149eee75a1091aef85be6a065f7db55f034b252acdbcf3155a4d1968e427584e41ade686f3eea719f9800c3a3b9cad1eacb632cfec09a1ca8ea063f4eb467c0bcbb67a86b6b790849340957db746dce213ee92e51e9d36d6c0ee46ae0e3b343a5fd6e108fc771cb1634eb308fdf02ef5845a7e9893d9323ed9689c5fe2c80519127008805560aef1f3f5c677226dc3bbe08ad481e8d94bff81ef3287c548e4e542ac33becc305f9811eb418c45f521a42d0ef0158a8bd08bd03bb12294e12e2b81e69e14c02bae2b77878eb1f330c898ff0d3ed93fa840b661025399f96f07256fed449950839bcaf143890742d22ba4207bb6d7570e9168f76195e818b5802e72f3bbcb46f5501b29f3a0eadc1977dce0fe320b64da7671962ecaf3c39757a8de946448de01b4b80d67d8fd2cbd4665440b6dbed5aa182fdb37f7f35963482a29701068d605b3ad3d319c794e3bb7caa05c30b80f019d332f0e671ed7423f0f6b2abe5da064143341ea88df204e0f13b516ed744375e9728723456cddb689ff4564a8f1877d1c7758a67084c909a6ba5cb559a674a7c10207c526c66c70f85bd000bf46b5337083c151cd372c59"
        db = get_firestore_client(serviceAccountEnc)
        db.collection("userTransactions") \
            .document(userId) \
            .collection("transactions") \
            .document(trxId) \
            .set({
                "amount": amount,
                "status": "PENDING",
            })
    except Exception as e:
        print("!!!! ERROR PUBLISH TO FIRESTORE")
        print(e)

def processCashback(rewardAmt, userid, pointsWallet):
    print(pointsWallet)
    key = f"userWalletInfo:{userid}:{pointsWallet}"
    pointsWalletdata = r.hgetall(key)
    ptsBalance = int(pointsWalletdata.get('walletBalance'))
    prevSignature = pointsWalletdata.get('signature')
    newPtsBalance = str(ptsBalance + rewardAmt)
    toBeSigned = str(newPtsBalance)+'|'+ pointsWallet+'|'+userid
    newSignature = signEd25519(toBeSigned)
    r.hset(key, mapping={"walletBalance": newPtsBalance, "signature": newSignature})
    return prevSignature, newSignature, str(ptsBalance), newPtsBalance

def sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, rewardAmount, paymentAmount, statusTrx, newWalletInfo, errDesc):
    constructDataHistory = {
        "transactionId": systemTrxId,
        "resellerId": params.userid,
        "createdBy": "backend",
        "createdOn": "",
        "transactionDate": formattedDate,
        "transactionEvent": "RETAIL_PDAM",
        "isPromoUsed": isPromoUsed,
        "promoId": params.promoCode,
        "promoAmount": rewardAmount,
        "paymentMethod": params.paymentChannel,
        "amount": paymentAmount,
        "status": statusTrx,
        "billNo": params.cart.customerNumber,
        "productId": params.cart.product,
        "latitude": params.location.latitude,
        "longitude": params.location.longitude,
        "walletInfo": newWalletInfo,
        "usePoinFlag": params.usePoinFlag,
        "errorDescription": errDesc,
        "billerCode": params.cart.billerCode
    }
    publishToPubsub(constructDataHistory, 'trx-to-sql-pdam', params.userid)

@app.post("/transactionRequestResellerPdam")
async def transactionRequestResellerPdam(params: TransactionRequestPdam):
    print(params)
    veryStart = time.perf_counter()
    
    isPromoUsed = params.promoCode not in (None, "", "-")
    # if params.promoCode == '-':
    #     isPromoUsed = False
    # else:
    #     isPromoUsed = True
    try:
        markup = 0
        parentId = None
        redisLockToken = acquireLockBlocking(params.userid, retry_interval=0.2, timeout=30)
        systemTrxId = 'TRX-' + getRandomNo()

        if not redisLockToken:
            currentTime = datetime.now()
            formattedDate = currentTime.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(currentTime.microsecond / 1000):03d}"
            sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, 0, 0, "ERR", "", "redis lock for user")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": "Locking error", "errorCode": "1031"}
            )

        start = time.perf_counter()
        resultCheck = checkMaxLoginAttempt(r, params.userid)
        end = time.perf_counter()
        print(f"Elapsed time to checkMaxLoginAttempt = {((end-start)*1000):.2f} ms")
        if not resultCheck:
            errMsg = "User PIN attempt exceeded, user is blocked"
            currentTime = datetime.now()
            formattedDate = currentTime.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(currentTime.microsecond / 1000):03d}"
            sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, 0, 0, "FAILED", "", errMsg)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": errMsg, "errorCode": "1021"}
            )

        billerCode = params.cart.billerCode
        productCategory = (params.cart.productCategory).upper()
        keyProduct = f"productDetail:{productCategory}:{billerCode}:{params.cart.product}"
        productInfo = r.hgetall(keyProduct)
        if not productInfo:
            triggerLockRelease(params.userid, redisLockToken)
            errMsg = "Product config doesn't exist in redis"
            currentTime = datetime.now()
            formattedDate = currentTime.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(currentTime.microsecond / 1000):03d}"
            sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, 0, 0, "FAILED", "", errMsg)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": errMsg, "errorCode": "4091"}
            )

        start = time.perf_counter()
        isDuplicate = checkDuplicateTrxId(r, params.appTrxId, params, systemTrxId)
        end = time.perf_counter()
        print(f"Elapsed time to checkDuplicateTrxId = {((end-start)*1000):.2f} ms")
        if isDuplicate:
            triggerLockRelease(params.userid, redisLockToken)
            errMsg = "Duplicate app TrxId"
            currentTime = datetime.now()
            formattedDate = currentTime.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(currentTime.microsecond / 1000):03d}"
            sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, 0, 0, "FAILED", "", errMsg)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"status": "error", "message": errMsg, "errorCode": "1022"}
            )

        rewardAmount = 0
        rewardType = None

        if params.paymentChannel == "DEPOSIT" or params.paymentChannel == "LOAN":
            if isPromoUsed:
                start = time.perf_counter()
                resultPromo, rewardType, rewardAmount = redeemPromoCodePdam(params.promoCode, params)
                print(f"---> Result promo : {resultPromo}")
                print(f"---> Reward type : {rewardType}")
                print(f"Reward amount: {rewardAmount}")
                end = time.perf_counter()
                print(f"Elapsed time to redeemPromoCodePdam = {((end-start)*1000):.2f} ms")

                if resultPromo:
                    print("initiate points topup later after balance deduction is successful. Continue using discount if it is direct deduction type")
                else:
                    rewardAmount = 0
                    rewardType = False
                    isPromoUsed = False
                    print("cancel points or voucher usage, return payment amount to normal in case it is discount")

            start = time.perf_counter()

            paymentAmount = int(params.cart.billAmount)

            markup, parentId = get_total_markup_for_child(params.userid)
            paymentAmount = paymentAmount + markup

            end = time.perf_counter()
            print(f"Elapsed time to compute PDAM paymentAmount = {((end-start)*1000):.2f} ms")
            print(f"Total Markup = {markup}")
            print(f"Parent ID = {parentId}")

            start = time.perf_counter()
            res, sucessFlag, ptsCharge, walletCharge, loanCharge, newWalletInfo, points = processDeduction(
                params.userid, paymentAmount, params.usePoinFlag, redisLockToken, rewardAmount
            )
            end = time.perf_counter()
            print(f"Elapsed time to processDeduction = {((end-start)*1000):.2f} ms")
            print(f"---> Elapsed time all = {((end-veryStart)*1000):.2f} ms")

            if res == "OK":
                statusTrx = "PENDING"
                if rewardType == "DISCOUNT" and resultPromo:
                    paymentAmount = paymentAmount - rewardAmount
                elif rewardType == "CASHBACK" and resultPromo:
                    prevSig, curSig, prevPtsBalance, newPtsBalance = processCashback(rewardAmount, params.userid, points[0]['walletId'])
                    promoQueue = {
                        "promoId": params.promoCode,
                        "userId": params.userid,
                        "trxId": systemTrxId,
                        "promoAmount": rewardAmount,
                        "walletId": points[0]['walletId'],
                        "prevSignature": prevSig,
                        "curSignature": curSig,
                        "previousPtsBalance": prevPtsBalance,
                        "newPtsBalance": newPtsBalance
                    }
                    publishToPubsub(promoQueue, 'cashback-points-trx', params.promoCode)

                    payloadCashbackGl = {
                        "event": "CASHBACK",
                        "tx_id": systemTrxId,
                        "amount": rewardAmount,
                        "account_id": points[0]['walletId'],
                        "occurred_at": str(datetime.now()),
                        "curr_bal": prevPtsBalance,
                        "curr_sig": prevSig,
                        "prev_sig": curSig,
                        "reseller_id": params.userid
                    }
                    print(payloadCashbackGl, flush=True)
                    publishToPubsub(payloadCashbackGl, 'cashback-gl-writer', params.promoCode)
                elif rewardType == "N/A":
                    pass
                else:
                    errMsg = f"reward type is wrong : {rewardType}"
                    currentTime = datetime.now()
                    formattedDate = currentTime.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(currentTime.microsecond / 1000):03d}"
                    sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, 0, 0, "FAILED", "", errMsg)
            else:
                statusTrx = "FAILED"
                errMsg = "Failed in processing deduction wallet, loan, or points"
                currentTime = datetime.now()
                formattedDate = currentTime.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(currentTime.microsecond / 1000):03d}"
                sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, 0, 0, "FAILED", "", errMsg)

            currentTime = datetime.now()
            formattedDate = currentTime.strftime('%Y-%m-%d %H:%M:%S.') + f"{int(currentTime.microsecond / 1000):03d}"
            sendLogPdam(systemTrxId, params, formattedDate, isPromoUsed, rewardAmount, paymentAmount, statusTrx, newWalletInfo, '')

            glRes = sendInfoToGL(
                systemTrxId,
                params.cart.product,
                paymentAmount,
                ptsCharge,
                walletCharge,
                loanCharge,
                params.paymentChannel,
                params.promoCode,
                rewardType,
                rewardAmount,
                params.userid,
                params.cart.customerNumber,
                parentId,
                markup
            )
            print(glRes)

            recordInFirestore(params.userid, systemTrxId, paymentAmount)
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"status": "OK", "message": "Transaction has been processed", "transactionId": systemTrxId}
            )
        else:
            print("SENDING REQUEST TO PAYMENT GATEWAY")
            
            triggerLockRelease(params.userid, redisLockToken)
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "status": "error",
                    "message": f"Unsupported paymentChannel: {params.paymentChannel}",
                    "errorCode": "4092"
                }
            )

    except Exception as e:
        triggerLockRelease(params.userid, redisLockToken)
        print(e)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "ERROR", "message": str(e)}
        )

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)