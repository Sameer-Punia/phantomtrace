from mangum import Mangum
from main import app

# Mangum adapts API Gateway REST/HTTP events to FastAPI ASGI
handler = Mangum(app, lifespan="off")