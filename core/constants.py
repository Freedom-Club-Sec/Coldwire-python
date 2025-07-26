# app metadata
VERSION       = "0.1"
APP_NAME      = "Coldwire"

# network defaults
LONGPOLL_MIN  = 5       # seconds
LONGPOLL_MAX  = 30      # seconds

# crypto parameters
AES_GCM_NONCE_LEN = 12  # bytes

OTP_PADDING_LENGTH = 2      # bytes
OTP_PADDING_LIMIT  = 1024   # bytes 


ARGON2_MEMORY     = 256 * 1024   # KB
ARGON2_ITERS      = 3
ARGON2_OUTPUT_LEN = 32           # bytes
ARGON2_SALT_LEN   = 32           # bytes
ARGON2_LANES      = 4
