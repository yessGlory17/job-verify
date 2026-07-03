# Container image for JobVerify — used by Glama to build the server and verify
# that it starts and answers MCP introspection (tools/list) requests.
#
# JobVerify speaks the Model Context Protocol over stdio, so the container just
# needs to launch the server; Glama drives it over stdin/stdout.
FROM python:3.12-slim

WORKDIR /app

# Copy project metadata and sources, then install the package + dependencies.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# MCP stdio server entry point (jobverify-mcp = jobverify_mcp.server:main).
ENTRYPOINT ["jobverify-mcp"]
