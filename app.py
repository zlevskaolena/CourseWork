import sys
sys.path.append('backend')
from backend.config import app
import backend.index


if __name__ == '__main__':
    app.run(host="localhost", port=8000)
