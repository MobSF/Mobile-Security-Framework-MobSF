# MobSF Run Instructions

## Prerequisites
- Docker Desktop running
- Git installed

## Start MobSF
From the project root:

```powershell
$env:HOME=$env:USERPROFILE
docker compose -f .\docker\docker-compose.yml up -d
```

## Access MobSF UI
Open:
- http://localhost:8080/login/

Default credentials:
- Username: mobsf
- Password: mobsf

## Check Service Status
```powershell
docker compose -f .\docker\docker-compose.yml ps
```

## View Logs
```powershell
docker compose -f .\docker\docker-compose.yml logs --tail 200
```

## Stop MobSF
```powershell
docker compose -f .\docker\docker-compose.yml down
```

## Notes
- This setup maps nginx from container port 4000 to host port 8080.
- If port 8080 is in use, update the nginx port mapping in docker/docker-compose.yml.
