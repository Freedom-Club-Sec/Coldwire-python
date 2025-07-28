# app metadata
APP_NAME      = "Coldwire"
APP_VERSION       = "0.1"

# network defaults (seconds)
LONGPOLL_MIN  = 5
LONGPOLL_MAX  = 30  

# crypto parameters (bytes)
AES_GCM_NONCE_LEN = 12

OTP_PAD_SIZE       = 11264
OTP_PADDING_LENGTH = 2
OTP_PADDING_LIMIT  = 1024

# NIST-specified key sizes (bytes) and metadata
ML_KEM_1024_NAME   = "Kyber1024"
ML_KEM_1024_SK_LEN = 3168
ML_KEM_1024_PK_LEN = 1568


ML_DSA_87_NAME     = "Dilithium5"  
ML_DSA_87_SK_LEN   = 4864
ML_DSA_87_PK_LEN   = 2592
ML_DSA_87_SIGN_LEN = 4595

# hash parameters
ARGON2_MEMORY      = 256 * 1024   # KB
ARGON2_ITERS       = 3
ARGON2_OUTPUT_LEN  = 32           # bytes
ARGON2_SALT_LEN    = 32           # bytes
ARGON2_LANES       = 4
