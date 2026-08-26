from fastapi import FastAPI

from database import Base, engine
import licensing

app = FastAPI(title="Voyager Licensing")

# Creates the ea_licenses table on first boot if it isn't there yet — fine
# for one table. Move to a real migration tool if this backend ever grows
# past this single purpose.
Base.metadata.create_all(bind=engine)

app.include_router(licensing.router)


@app.get("/")
def health_check():
    return {"status": "ok", "service": "voyager-licensing"}