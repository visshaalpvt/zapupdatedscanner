import sys
sys.path.insert(0, r'C:\Users\LENOVO\Downloads\zap-scanner-v2\scripts')

from zap_core import start_local_zap, connect_zap, stop_local_zap

print('[TEST] starting local ZAP...')
try:
    start_local_zap(api_key='zap-local-key', api_url='http://127.0.0.1:8080')
    zap = connect_zap(api_key='zap-local-key', api_url='http://127.0.0.1:8080')
    print('[TEST] startup/connection check passed')
    print('[TEST] connected object:', type(zap).__name__)
finally:
    stop_local_zap(api_url='http://127.0.0.1:8080', api_key='zap-local-key')
    print('[TEST] shutdown complete')
