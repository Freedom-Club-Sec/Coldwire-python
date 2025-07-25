import traceback

def thread_failsafe_wrapper(target, stop_flag, ui_queue, *args, **kwargs):
    try:
        target(*args, **kwargs)
    except Exception:
        traceback.print_exc() 
        stop_flag.set()
        ui_queue.put({"type": "exit"})
