# Stage 1: Build the React/Vite app
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# API URL baked into the frontend bundle at build time
ARG VITE_API_URL=http://localhost:3102
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# Stage 2: Serve static files with nginx (minimal runtime image)
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
