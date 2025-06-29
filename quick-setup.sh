#!/bin/bash

# quick-setup.sh - Get SickoScoop working fast with current structure
echo "🚀 SickoScoop Quick Setup - Get Working Fast!"
echo "=============================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check current directory
if [ ! -d "sickoscoop-frontend" ] && [ ! -d "backend" ]; then
    print_error "Please run this script from your main sickoscoop directory"
    print_info "You should see 'sickoscoop-frontend' and 'backend' directories"
    exit 1
fi

print_success "Found your current structure"

# Step 1: Organize directories
print_info "Step 1: Organizing directories..."

# Move frontend to the standard name
if [ -d "sickoscoop-frontend" ] && [ ! -d "frontend" ]; then
    mv sickoscoop-frontend frontend
    print_success "Renamed sickoscoop-frontend to frontend"
fi

# Copy backend files to root
if [ -d "backend" ]; then
    print_info "Copying backend files to root..."
    
    # Copy server file
    if [ -f "backend/server.js" ]; then
        cp backend/server.js ./
        print_success "Copied server.js to root"
    elif [ -f "backend/enhanced-server.js" ]; then
        cp backend/enhanced-server.js ./server.js
        print_success "Copied enhanced-server.js as server.js"
    else
        print_error "No server file found in backend directory"
        exit 1
    fi
    
    # Copy package.json
    if [ -f "backend/package.json" ]; then
        cp backend/package.json ./
        print_success "Copied package.json to root"
    else
        print_warning "No package.json found in backend, will create one"
    fi
    
    # Copy .env file
    if [ -f "backend/.env" ]; then
        cp backend/.env ./
        print_success "Copied .env to root"
    elif [ -f ".env" ]; then
        print_success ".env already in root"
    else
        print_warning "No .env file found, will create template"
    fi
fi

# Step 2: Create/update package.json if needed
print_info "Step 2: Setting up package.json..."

if [ ! -f "package.json" ]; then
    print_info "Creating package.json..."
    cat > package.json << 'PACKAGE_EOF'
{
  "name": "sickoscoop",
  "version": "1.0.0",
  "description": "SickoScoop social media platform",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "build:frontend": "cd frontend && npm install && npm run build",
    "build:complete": "npm run build:frontend && cp -r frontend/build ./build",
    "deploy": "npm run build:complete && npm start",
    "test": "echo \"No tests yet\" && exit 0"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "multer": "^1.4.5-lts.1",
    "aws-sdk": "^2.1450.0",
    "socket.io": "^4.7.2",
    "express-rate-limit": "^6.10.0",
    "helmet": "^7.0.0",
    "compression": "^1.7.4",
    "sharp": "^0.32.5",
    "file-type": "^18.5.0",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  },
  "engines": {
    "node": ">=16.0.0"
  }
}
PACKAGE_EOF
    print_success "Created package.json"
fi

# Step 3: Create/update .env file if needed
print_info "Step 3: Setting up environment variables..."

if [ ! -f ".env" ]; then
    print_info "Creating .env template..."
    cat > .env << 'ENV_EOF'
# SickoScoop Environment Variables

# Database Connection
MONGODB_URI=mongodb+srv://namekreator-user:5z9OpLZ34.7@cluster0.soprv0r.mongodb.net/sickoscoop?retryWrites=true&w=majority

# JWT Secret
JWT_SECRET=sickoscoop_super_secret_jwt_key_2025_production_ready_secure_token

# Server Port
PORT=3001

# DigitalOcean Spaces (REQUIRED for file uploads)
DO_SPACES_KEY=DO801ERXFLCGZL4NNBEX
DO_SPACES_SECRET=lVfcC4ITcH42OuG07ltRx/toUdlLbP25eEOlmsO1c0Q
DO_SPACES_BUCKET=sickoscoop-media
DO_SPACES_REGION=sfo2
DO_SPACES_ENDPOINT=sfo2.digitaloceanspaces.com

# Environment
NODE_ENV=production
ENV_EOF
    print_success "Created .env template with your existing values"
fi

print_info "Step 4: Installing backend dependencies..."
if npm install; then
    print_success "Backend dependencies installed"
else
    print_error "Failed to install backend dependencies"
    exit 1
fi

print_info "Step 5: Building React frontend..."
if [ -d "frontend" ]; then
    cd frontend
    
    if [ ! -d "node_modules" ]; then
        print_info "Installing frontend dependencies..."
        npm install
    fi
    
    if npm run build; then
        print_success "Frontend built successfully"
        cd ..
        
        if [ -d "frontend/build" ]; then
            rm -rf build
            cp -r frontend/build ./build
            print_success "Frontend build copied to backend"
        else
            print_error "Frontend build directory not found"
            exit 1
        fi
    else
        print_error "Frontend build failed"
        cd ..
        exit 1
    fi
else
    print_error "Frontend directory not found"
    exit 1
fi

echo ""
echo "🎉 SickoScoop Quick Setup Complete!"
echo "=================================="
echo ""
print_success "✅ Files organized correctly"
print_success "✅ Dependencies installed"
print_success "✅ Frontend built and ready"
echo ""
echo "🚀 Ready to launch!"
echo "=================="
echo ""
echo "🧪 Test locally:"
echo "   npm start"
echo "   Visit: http://localhost:3001"
echo ""
print_success "🌟 Setup complete!"
