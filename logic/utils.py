import traceback

def check_str_high_entropy(s: str) -> bool:
    # strings under 8 characters long are insecure no matter the language.
    if len(s) < 8:
        return False

    # if string is not all ascii, just assume it has enough entropy.
    if not s.isascii():
        return True

    # Check if string is all lowercase or uppercase
    if s.lower() == s or s.upper() == s:
        return False

    # if all digits
    if s.isdigit():
        return False

    # if doesn't contain digits
    if not any(c.isdigit() for c in s):
        return False

    # Check for special characters, spaces, etc
    if not any(not c.isalnum() for c in s):
        return False

    return True


def thread_failsafe_wrapper(target, stop_flag, ui_queue, *args, **kwargs):
    try:
        target(*args, **kwargs)
    except Exception:
        traceback.print_exc() 
        stop_flag.set()
        ui_queue.put({"type": "exit"})

