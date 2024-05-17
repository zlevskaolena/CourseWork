from backend.config import app
import backend.index
import sys
sys.path.append('backend')

if __name__ == '__main__':
    app.run(host="localhost", port=8000)
