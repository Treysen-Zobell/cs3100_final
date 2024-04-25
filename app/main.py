import json

import uvicorn
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.middleware.cors import CORSMiddleware

from app.utils.environment import API_URL
from app.routes import auth
from app.utils.log import create_logger

logger = create_logger(__name__)


def generate_unique_id(route: APIRoute) -> str:
    """
    Generate a unique id for a route using its name
    :param route: Route object
    :return: Name of the route
    """
    return f"{route.name}"


# Create application
app = FastAPI(
    generate_unique_id_function=generate_unique_id,
    servers=json.loads(API_URL),
    version="v0.0.0",
    title="Dashboard API",
    description="An API for interfacing with services necessary for the NOC Dashboard, such as CMS, SMx, and Incognito",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create versions
app_v1 = FastAPI()

# Include routers
app_v1.include_router(auth.router)

# Connect versions
app.mount("/v1", app_v1)


# Run using uvicorn
if __name__ == "__main__":
    uvicorn.run("main:app", host=API_URL, port=8003, reload=True)
