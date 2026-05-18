# nginx image that bundles the pre-built React SPA.
#
# Build context: this Dockerfile is built from the project root so it can
# COPY the compiled dashboard output.
#
# Usage (from project root):
#   npm --prefix compliance-dashboard run build
#   docker build -f nginx/Dockerfile -t compliance-nginx .

FROM nginx:1.27-alpine

# Remove default nginx static files
RUN rm -rf /usr/share/nginx/html/*

# Copy the Vite production build output
COPY compliance-dashboard/dist /usr/share/nginx/html

# nginx.conf is mounted via docker-compose volume at runtime,
# but include a sane default so the image is self-contained for testing.
COPY nginx/nginx.conf /etc/nginx/nginx.conf

EXPOSE 80
