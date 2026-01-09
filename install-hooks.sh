#!/bin/bash

# Script per instal·lar git hooks personalitzats
# Executa: ./install-hooks.sh

echo "📦 Instal·lant Git Hooks per Minerva..."

# Configurar Git per usar el directori .git-hooks
git config core.hooksPath .git-hooks

if [ $? -eq 0 ]; then
    echo "✅ Git hooks instal·lats correctament!"
    echo ""
    echo "Hooks actius:"
    echo "  - pre-commit: Executa tests automàtics abans de cada commit"
    echo ""
    echo "Per desactivar els hooks temporalment:"
    echo "  git commit --no-verify"
    echo ""
    echo "Per desinstal·lar els hooks:"
    echo "  git config --unset core.hooksPath"
else
    echo "❌ Error instal·lant hooks"
    exit 1
fi
