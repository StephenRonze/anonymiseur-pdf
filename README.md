# Anonymiseur de PDF

Anonymiseur de PDF **100 % local** : aucune donnée n'est envoyée sur internet.

## Principe

- **PDF natifs** (texte sélectionnable) : vraie suppression du texte via les
  « redactions » de PyMuPDF. Le texte est **retiré** du fichier, pas seulement
  masqué à l'écran.
- **PDF scannés** (images) : OCR local (Tesseract) pour localiser les zones
  sensibles, puis rectangles opaques dessinés par-dessus.
- Nettoyage des métadonnées (auteur, logiciel de création, etc.).

## Détections automatiques

N° de Sécurité sociale (NIR), numéro fiscal, référence d'avis, IBAN français,
carte bancaire, n° de compte, SIRET/SIREN, e-mail, téléphone français… plus vos
termes personnalisés via `termes.txt` (un terme par ligne).

## Installation

```bash
pip install pymupdf pytesseract Pillow
```

Moteur Tesseract à installer sur la machine :

- Windows : https://github.com/UB-Mannheim/tesseract/wiki
- macOS : `brew install tesseract tesseract-lang`
- Linux : `sudo apt install tesseract-ocr tesseract-ocr-fra`

## Utilisation

```bash
# Produire le PDF anonymisé
python anonymiseur.py entree.pdf sortie.pdf

# Détecter sans modifier (mode rapport)
python anonymiseur.py entree.pdf --rapport

# Termes personnalisés
python anonymiseur.py entree.pdf sortie.pdf --termes termes.txt

# Ignorer les pages scannées
python anonymiseur.py entree.pdf sortie.pdf --no-ocr
```

> ⚠️ Vérifiez visuellement le résultat avant tout partage.
