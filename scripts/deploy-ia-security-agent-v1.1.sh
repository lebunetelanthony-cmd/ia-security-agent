#!/usr/bin/env bash
#
# =====================================================================
# IA SECURITY AGENT DEPLOYMENT V1.1 — NIGHTLY LLM V5
# Script de déploiement / configuration
# =====================================================================
#
# OBJECTIF
# --------
# Ce script simplifie le déploiement de IA Security Agent Deployment V1
# sur une nouvelle machine sans modifier le package V1 gelé.
#
# Le véritable installateur reste :
#
#     install-ia-security-agent
#
# Ce script :
#   1. vérifie l'archive et son fichier SHA256 ;
#   2. contrôle l'intégrité de l'archive ;
#   3. extrait la release dans /tmp ;
#   4. contrôle l'intégrité interne du package ;
#   5. exécute le preflight ;
#   6. construit la commande d'installation à partir des variables ci-dessous ;
#   7. appelle l'installateur officiel avec sudo ;
#   8. supprime l'extraction temporaire uniquement en cas de succès ;
#   9. conserve l'extraction temporaire en cas d'échec pour diagnostic.
#
# Le script NE MODIFIE PAS le package Deployment V1 gelé.
#
# =====================================================================
# PRÉREQUIS UBUNTU / DEBIAN
# =====================================================================
#
# IA Security Agent utilise notamment :
#   python3 >= 3.10
#   systemd / systemctl / systemd-analyze
#   sha256sum
#   runuser
#   dpkg-query
#   ip
#   ss
#   findmnt
#   tar
#
# Paquets Ubuntu / Debian principaux :
#
#   sudo apt update
#   sudo apt install -y \
#       python3 \
#       systemd \
#       coreutils \
#       util-linux \
#       dpkg \
#       iproute2 \
#       tar
#
# Sur Ubuntu Server, beaucoup sont normalement déjà présents.
#
# =====================================================================
# PRÉREQUIS OPTIONNEL — NIGHTLY LLM
# =====================================================================
#
# Si ENABLE_NIGHTLY_LLM="yes" :
#   - Ollama doit être installé ;
#   - Ollama doit être accessible localement ;
#   - le modèle configuré plus bas doit déjà être téléchargé.
#
# Vérification :
#
#   ollama list
#
# =====================================================================
# EXPLICATION DES LIGNES D'INSTALLATION
# =====================================================================
#
# 1. Vérification de l'archive :
#
#      sha256sum -c ia-security-agent-deployment-v1.tar.gz.sha256
#
#    Vérifie que l'archive transférée est identique à la release gelée.
#
# 2. Extraction :
#
#      tar -xzf ia-security-agent-deployment-v1.tar.gz
#
# 3. Vérification interne :
#
#      sha256sum -c CONTROL-SHA256SUMS
#
# 4. Préflight :
#
#      ./bin/preflight-ia-security-agent
#
# 5. Installation :
#
#      sudo ./install-ia-security-agent [...]
#
#    L'installateur installe le control plane, crée une instance propre
#    à la machine, crée la baseline locale, exécute le premier cycle,
#    génère les unités systemd et active le timer principal.
#
# =====================================================================
#                 VARIABLES À PERSONNALISER
# =====================================================================

ARCHIVE_NAME="ia-security-agent-deployment-v1.1.tar.gz"
ARCHIVE_SHA_NAME="ia-security-agent-deployment-v1.1.tar.gz.sha256"

CONTROL_ROOT="/opt/ia-security-agent/v1"
RUNTIME_ROOT="/data/ia-local/security-audit"
UNIT_DIR="/etc/systemd/system"
INSTALLER_STATE_ROOT="/var/lib/ia-security-agent-installer"

# Laisser vide pour sélection automatique par l'installateur.
SERVICE_USER=""
SERVICE_GROUP=""

TIMEZONE="Europe/Paris"
CORE_SCHEDULE="hourly"
RANDOMIZED_DELAY_SEC="5min"

# Nightly LLM : yes / no
ENABLE_NIGHTLY_LLM="no"
LLM_ENDPOINT="http://127.0.0.1:11434"
LLM_MODEL="qwen3:4b-instruct"
LLM_TIME="03:00:00"

# =====================================================================
#               FIN DES VARIABLES À PERSONNALISER
# =====================================================================

set -euo pipefail
export LC_ALL=C
export LANG=C
export PYTHONDONTWRITEBYTECODE=1
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 027

die() {
    echo >&2
    echo "ERREUR : $*" >&2
    echo >&2
    exit 1
}

require_command() {
    local command_name="$1"
    command -v "$command_name" >/dev/null 2>&1 || \
        die "commande requise absente : $command_name"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE="$SCRIPT_DIR/$ARCHIVE_NAME"
ARCHIVE_SHA="$SCRIPT_DIR/$ARCHIVE_SHA_NAME"

echo
echo "====================================================================="
echo " IA SECURITY AGENT DEPLOYMENT V1.1 — NIGHTLY LLM V5"
echo " Déploiement / configuration"
echo "====================================================================="
echo "Répertoire du script : $SCRIPT_DIR"
echo

for command_name in sha256sum tar python3 sudo grep mktemp; do
    require_command "$command_name"
done

[ -f "$ARCHIVE" ] || die "archive introuvable : $ARCHIVE"
[ -f "$ARCHIVE_SHA" ] || die "fichier SHA256 introuvable : $ARCHIVE_SHA"

echo "=== Vérification SHA256 de l'archive ==="
(
    cd "$SCRIPT_DIR"
    sha256sum -c "$ARCHIVE_SHA_NAME"
)
echo "ARCHIVE_INTEGRITY=VALID"

TEST_ROOT="$(mktemp -d /tmp/ia-security-agent-deploy.XXXXXX)"
EXTRACT_ROOT="$TEST_ROOT/release"
PACKAGE_ROOT="$EXTRACT_ROOT/ia-security-agent-deployment-v1.1"
mkdir -p "$EXTRACT_ROOT"

preserve_failure() {
    echo
    echo "====================================================================="
    echo " DÉPLOIEMENT INTERROMPU"
    echo "====================================================================="
    echo "Les fichiers temporaires sont conservés pour diagnostic :"
    echo "    $TEST_ROOT"
    echo "Ne relance pas aveuglément la même tentative sans analyser la cause."
}

trap preserve_failure ERR
trap preserve_failure INT TERM

echo
echo "=== Extraction temporaire ==="
tar -xzf "$ARCHIVE" -C "$EXTRACT_ROOT"

[ -d "$PACKAGE_ROOT" ] || die "package extrait introuvable : $PACKAGE_ROOT"

INSTALLER="$PACKAGE_ROOT/install-ia-security-agent"
PREFLIGHT="$PACKAGE_ROOT/bin/preflight-ia-security-agent"

[ -x "$INSTALLER" ] || die "installateur final introuvable : $INSTALLER"
[ -x "$PREFLIGHT" ] || die "preflight introuvable : $PREFLIGHT"

echo
echo "=== Vérification du control plane ==="
(
    cd "$PACKAGE_ROOT"
    sha256sum -c CONTROL-SHA256SUMS
)
echo "CONTROL_PLANE_INTEGRITY=VALID"

echo
echo "=== Préflight ==="
PREFLIGHT_OUTPUT="$("$PREFLIGHT")"
printf '%s\n' "$PREFLIGHT_OUTPUT"

printf '%s\n' "$PREFLIGHT_OUTPUT" | grep -Fq '"status": "VALID"' || \
    die "le préflight n'a pas retourné status=VALID"

echo "PREFLIGHT=VALID"

case "$ENABLE_NIGHTLY_LLM" in
    yes|no) ;;
    *) die "ENABLE_NIGHTLY_LLM doit valoir yes ou no" ;;
esac

CMD=(
    "$INSTALLER"
    --control-root "$CONTROL_ROOT"
    --runtime-root "$RUNTIME_ROOT"
    --unit-dir "$UNIT_DIR"
    --installer-state-root "$INSTALLER_STATE_ROOT"
    --timezone "$TIMEZONE"
    --core-schedule "$CORE_SCHEDULE"
    --randomized-delay-sec "$RANDOMIZED_DELAY_SEC"
)

if [ -n "$SERVICE_USER" ]; then
    CMD+=(--service-user "$SERVICE_USER")
fi

if [ -n "$SERVICE_GROUP" ]; then
    CMD+=(--service-group "$SERVICE_GROUP")
fi

if [ "$ENABLE_NIGHTLY_LLM" = "yes" ]; then
    CMD+=(
        --enable-nightly-llm
        --llm-endpoint "$LLM_ENDPOINT"
        --llm-model "$LLM_MODEL"
        --llm-time "$LLM_TIME"
    )
fi

echo
echo "====================================================================="
echo " CONFIGURATION DE CETTE MACHINE"
echo "====================================================================="
echo "CONTROL_ROOT             = $CONTROL_ROOT"
echo "RUNTIME_ROOT             = $RUNTIME_ROOT"
echo "UNIT_DIR                 = $UNIT_DIR"
echo "INSTALLER_STATE_ROOT     = $INSTALLER_STATE_ROOT"
echo "SERVICE_USER             = ${SERVICE_USER:-AUTO}"
echo "SERVICE_GROUP            = ${SERVICE_GROUP:-AUTO}"
echo "TIMEZONE                 = $TIMEZONE"
echo "CORE_SCHEDULE            = $CORE_SCHEDULE"
echo "RANDOMIZED_DELAY_SEC     = $RANDOMIZED_DELAY_SEC"
echo "NIGHTLY_LLM              = $ENABLE_NIGHTLY_LLM"

if [ "$ENABLE_NIGHTLY_LLM" = "yes" ]; then
    echo "LLM_ENDPOINT             = $LLM_ENDPOINT"
    echo "LLM_MODEL                = $LLM_MODEL"
    echo "LLM_TIME                 = $LLM_TIME"
fi

echo
echo "Archive source : $ARCHIVE"
echo "Package temporaire : $PACKAGE_ROOT"
echo

echo "====================================================================="
echo " LANCEMENT DE L'INSTALLATEUR OFFICIEL"
echo "====================================================================="
echo

set +e
sudo "${CMD[@]}"
INSTALL_RC=$?
set -e

if [ "$INSTALL_RC" -ne 0 ]; then
    trap - ERR INT TERM
    echo
    echo "INSTALLATION_STATUS=REFUSED"
    echo "INSTALLATION_EXIT_CODE=$INSTALL_RC"
    echo "Extraction temporaire conservée : $TEST_ROOT"
    exit "$INSTALL_RC"
fi

trap - ERR INT TERM
rm -rf -- "$TEST_ROOT"

echo
echo "====================================================================="
echo " INSTALLATION TERMINÉE"
echo "====================================================================="
echo "INSTALLATION_STATUS=VALID"
echo "Control plane : $CONTROL_ROOT"
echo "Runtime       : $RUNTIME_ROOT"
echo "Timer         : ia-security-agent.timer"

if [ "$ENABLE_NIGHTLY_LLM" = "yes" ]; then
    echo "Timer LLM     : ia-security-agent-nightly-llm.timer"
fi

echo
echo "Opération terminée, vous pouvez fermer cette fenêtre."
echo
