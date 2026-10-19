# Extensão OpenPass para navegador

Preenche senhas salvas no seu cofre OpenPass direto nas páginas, oferece salvar
novos logins depois que você entra em um site, gera senhas fortes e mostra os
códigos 2FA (TOTP) — o equivalente ao que a extensão do Bitwarden faz, apontando
para o **seu** servidor.

## O que ela faz

- **Preenchimento automático** — ao abrir a tela de login, se houver apenas um
  login salvo para o site, ele é preenchido sozinho.
- **Menu no campo** — ao focar um campo de usuário ou senha vazio, aparece uma
  lista dos logins daquele site para escolher.
- **Salvar e atualizar** — depois de enviar um formulário, a extensão oferece
  salvar o login; se já existir um com o mesmo usuário, oferece **atualizar a
  senha** em vez de duplicar.
- **Códigos 2FA** — para itens com segredo de autenticador salvo, o popup mostra
  o código de 6 dígitos com contagem regressiva e copia para a área de
  transferência.
- **Gerador de senhas** — mesma implementação do painel; a senha é gerada no
  servidor com `crypto/rand`.

## Instalação

1. Gere uma chave de API no painel: **Chaves de API → Nova chave**, com as
   permissões `entries:read` e `entries:write`.
2. Abra `chrome://extensions`, ative o **Modo do desenvolvedor**.
3. Clique em **Carregar sem compactação** e selecione esta pasta (`extension/`).
4. Abra as **Opções** da extensão e informe:
   - **URL do servidor**: ex. `https://openpass.mlluizdevtech.com.br`
   - **Chave de API**: o valor gerado no passo 1.
5. Clique em **Testar conexão** — deve responder quantos cofres a chave vê.

## Como o segredo circula (modelo de segurança)

- A chave de API fica em `chrome.storage.local` (nunca sincronizada) e é usada
  **apenas pelo service worker** (`background.js`). O content script, que roda
  dentro das páginas, nunca a vê.
- O content script pede ao worker os logins que casam com a URL atual
  (`GET /api/v1/entries/match`), que devolve **só metadados** por padrão. O valor
  só é buscado (`reveal=1`) quando você escolhe um item.
- O preenchimento é feito pela extensão; a senha não passa por `postMessage`
  entre páginas nem é gravada no DOM de forma mais exposta do que o próprio
  formulário do site.
- O servidor decide o que casar: apenas hosts iguais, subdomínios ou o mesmo
  domínio registrável. Um domínio parecido (`banco.exemplo.evil.test`) **não**
  recebe as credenciais do banco.
- O segredo TOTP é guardado cifrado em coluna própria; a API nunca o devolve,
  apenas o código gerado.

## Limitações conhecidas

- Só Chrome/Edge (Manifest V3). Firefox exige ajustes no `manifest.json`.
- Sem sincronização de configuração entre máquinas: a chave é por navegador.
- Preenchimento automático só age quando há **um** login para o site; com vários,
  a escolha é sempre sua.
