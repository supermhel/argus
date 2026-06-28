FROM nginx:alpine
COPY services/ws7-dashboard /usr/share/nginx/html
EXPOSE 80
# Static single-file dashboard. Set window.INVENTORY_API in index.html (or via a
# small env-substituted config) to point at the live WS-6 service.
