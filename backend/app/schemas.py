from pydantic import BaseModel


class ConfigSource(BaseModel):
    key: str
    label: str
    server_id: str
    path: str


class ServerInfo(BaseModel):
    id: str
    name: str
    path: str
    shortname: str
    script: str
    status: str

    class Config:
        orm_mode = True
