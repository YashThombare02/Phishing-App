import sys
print("Python executable:", sys.executable)
print("Python version:", sys.version)
print("Python path:", sys.path)

# Try importing the problematic modules
try:
    import bs4
    print("bs4 version:", bs4.__version__)
except ImportError:
    print("bs4 import failed")

try:
    import xgboost
    print("xgboost version:", xgboost.__version__)
except ImportError:
    print("xgboost import failed")

try:
    import whois
    print("whois version:", whois.__version__)
except ImportError:
    print("whois import failed")
