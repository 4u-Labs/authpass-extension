# 🛡️ AuthPass — Autenticador 2FA Zero-Knowledge
### **Extensão Chrome MV3 para Autenticação em Dois Fatores com Criptografia Militar e Retenção Zero**

<p align="center">
  <img src="https://img.shields.io/badge/Manifest-V3-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Manifest V3" />
  <img src="https://img.shields.io/badge/Chrome_Extension-Official-10b981?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Chrome Extension" />
  <img src="https://img.shields.io/badge/Privacidade-100%25_Local-6d4aff?style=for-the-badge" alt="Privacidade" />
  <a href="https://4u.ia.br/app/authpass/"><img src="https://img.shields.io/badge/Web_App-4U.IA.BR-0ea5e9?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Web App" /></a>
  <a href="https://chromewebstore.google.com/search/4u.ia.br"><img src="https://img.shields.io/badge/Chrome_Web_Store-Dispon%C3%ADvel-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Chrome Web Store" /></a>
</p>

---

## 📖 Visão Geral

Extensão para Google Chrome (Manifest V3) que traz o poderoso autenticador **AuthPass** diretamente para a barra de ferramentas do seu navegador. 

Permite gerar códigos 2FA (TOTP - RFC 6238) instantâneos com cópia em 1 clique, proteger seu cofre com PIN e criptografia militar **AES-GCM de 256 bits derivada via PBKDF2**, e ler códigos QR a partir de capturas de tela.

Parte integrante do ecossistema de soluções de alta performance da **[4U.IA.BR](https://4u.ia.br)**.

---

## ✨ Principais Recursos

- ⏱️ Geração instantânea de senhas temporárias TOTP (RFC 6238) com contador regressivo de 30 segundos
- 🔒 Cofre Zero-Knowledge protegido por PIN e criptografia AES-GCM 256 bits no cliente
- 🆘 Chave Mestra de Emergência para recuperação rápida de acesso em caso de esquecimento de PIN
- 📷 Leitor integrado de QR Code a partir de capturas de tela e imagens salvas
- 📋 Cópia rápida com 1 clique direto para a área de transferência
- 🛡️ Retenção Zero: nenhuma chave ou segredo é enviado a servidores externos

---

## 🚀 Como Instalar e Testar no Google Chrome / Chromium

1. Clone este repositório ou baixe o código-fonte:
   ```bash
   git clone git@github.com:4u-Labs/authpass-extension.git
   ```
2. Abra o Google Chrome ou qualquer navegador baseado em Chromium (Brave, Edge, Vivaldi).
3. Acesse a URL: `chrome://extensions/`
4. No canto superior direito, ative a chave **Modo do desenvolvedor**.
5. No canto superior esquerdo, clique no botão **Carregar sem compactação** (*Load unpacked*).
6. Selecione esta pasta.
7. A extensão estará imediatamente ativa na sua barra de ferramentas!

---

## 👨‍💻 Autor & Créditos

- **Organização:** [4u-Labs](https://github.com/4u-Labs)
- **Portal Oficial:** [4U.IA.BR](https://4u.ia.br)
- **Autor:** Fabiano Braga (ORCID: [0009-0004-5936-5060](https://orcid.org/0009-0004-5936-5060))
- **Licença:** MIT / Uso Proprietário 4U.IA.BR
