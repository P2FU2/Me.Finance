# ===========================================
# Projeto Servidor e Painel Administrativo
# ===========================================

Este projeto consiste em um servidor Express.js que fornece uma API para um painel administrativo. O painel permite que os administradores adicionem, editem e removam postagens. O servidor se conecta a um banco de dados MySQL para armazenar as postagens.

## Como Iniciar o Servidor

* Abra o terminal e navegue até o diretório do projeto.
* Execute o comando `node index.js` para iniciar o servidor.
* O servidor estará rodando na porta 3000. Abra um navegador e acesse `http://localhost:3000` para ver a mensagem "Servidor funcionando".

## Como Parar o Servidor

* No terminal onde o servidor está rodando, pressione `Ctrl+C` para parar o servidor.

## Como Tornar o Servidor Online

Para tornar o servidor acessível pela internet, você pode usar serviços como o [ngrok](https://ngrok.com/). Siga os passos abaixo:

* Baixe e instale o ngrok.
* No terminal, execute o comando `ngrok http 3000`.
* O ngrok fornecerá um URL público que você pode usar para acessar o servidor pela internet.

## Problemas Comuns e Soluções

### Erro de Conexão com o Banco de Dados

* Se você receber um erro de conexão com o banco de dados, verifique se o MySQL está rodando e se as credenciais no arquivo `index.js` estão corretas.

### Erro de Porta em Uso

* Se você receber um erro dizendo que a porta 3000 já está em uso, outra aplicação pode estar usando essa porta. Você pode mudar a porta no arquivo `index.js` ou parar a outra aplicação.

### Erro de Módulo Não Encontrado

* Se você receber um erro de módulo não encontrado, você pode ter esquecido de instalar as dependências. No terminal, execute o comando `npm install` para instalar as dependências.

## ===========================================
## TUTORIAL DE DESENVOLVIMENTO WEB COM NODE.JS
## ===========================================

Este tutorial é baseado em uma série de interações e problemas enfrentados durante o desenvolvimento de um projeto web. Vamos explorar desde o básico até a solução de problemas mais complexos.

## ÍNDICE

* 1. Configuração Inicial
* 2. Banco de Dados
* 3. Autenticação de Usuário
* 4. Erros Comuns e Soluções
* 5. Dicas e Melhores Práticas
* 6. Estilo do CSS

## 1. CONFIGURAÇÃO INICIAL

Antes de começar, é fundamental configurar corretamente o ambiente de desenvolvimento. Isso inclui instalar o Node.js, configurar o NPM (Node Package Manager) e instalar os pacotes necessários.

* Instale o Node.js: Vá para [nodejs.org](https://nodejs.org/) e baixe a versão mais recente.
* Verifique a instalação executando: 
* $ node -v
* $ npm -v

* Inicie um novo projeto com:
* $ npm init


Ao longo do nosso projeto, você vai precisar de vários pacotes. Instale-os conforme necessário usando o npm.
* Por exemplo:
* $ npm install express ejs mysql


## 2. BANCO DE DADOS

O MySQL foi o banco de dados escolhido para este projeto. Para interagir com ele, usamos o pacote 'mysql' do Node.js.

* Ter um servidor MySQL rodando.
* Conhecer as credenciais do banco (host, usuário, senha).
* Criar uma conexão usando o pacote 'mysql'.

Durante o desenvolvimento, enfrentamos alguns problemas com a conexão. Aqui está um checklist para solucionar problemas de conexão:

* Verifique se o servidor MySQL está rodando.
* Garanta que as credenciais estão corretas.
* Use um cliente MySQL, como o MySQL Workbench, para testar a conexão diretamente.

## 3. AUTENTICAÇÃO DE USUÁRIO

A autenticação é uma parte crucial de muitos aplicativos web. No nosso caso, usamos o Passport.js para autenticar os usuários.

* Armazene as senhas de forma segura. No nosso caso, usamos o bcrypt para hashear as senhas.
* Use sessões para manter os usuários logados.
* Garanta que as rotas protegidas verifiquem se o usuário está autenticado.

## 4. ERROS COMUNS E SOLUÇÕES

Ao longo do desenvolvimento, vários erros podem surgir. Aqui estão alguns que encontramos e suas soluções:

* "message is not defined" em EJS:
- Sempre passe todas as variáveis que seu template EJS espera, mesmo que sejam nulas ou strings vazias.

## 5. DICAS E MELHORES PRÁTICAS

* Estruture seu projeto de forma clara. Separe a lógica de negócios, rotas, configurações, etc.
* Comente seu código! Isso ajuda outros desenvolvedores (e você no futuro) a entender o que cada parte faz.
* Mantenha-se atualizado. As tecnologias evoluem rapidamente. O que é uma prática padrão hoje pode não ser amanhã.

## 6. ESTILO DO CSS

Existem três metodologias principais para estilizar CSS: BEM, SMACSS e OOCSS. Essas metodologias foram criadas para ajudar os desenvolvedores a escrever CSS de maneira mais estruturada, modular e reutilizável. Nesse projeto usamos uma mistura dos tres.

## 1. BEM (Block, Element, Modifier)

**Introdução:** 
BEM é uma abordagem que visa criar componentes reutilizáveis e robustos. O nome BEM é um acrônimo para os três componentes principais da metodologia:

* **Block**: Um componente independente que pode ser reutilizado em várias partes da UI.
* **Element**: Uma parte de um bloco que não tem sentido isolado.
* **Modifier**: Uma variante ou extensão de um bloco ou elemento.

**Prós:**
* Clareza e Consistência: A estrutura de nomenclatura do BEM é fácil de entender, tornando mais claro o propósito de cada classe.
* Reutilização: Facilita a criação de componentes reutilizáveis.
* Menos Cascata: Reduz o risco de efeitos colaterais indesejados.
* Facilita a Manutenção: Saber como um componente é usado e como ele deve aparecer em diferentes estados é mais simples.

**Contras:**
* Nomes de Classe Longos: Pode parecer repetitivo.
* Curva de Aprendizado: Pode ser desafiador para iniciantes.
* Verbosidade: Pode resultar em muitas classes em um único elemento.

## 2. SMACSS (Scalable and Modular Architecture for CSS)

**Introdução:** 
SMACSS é mais um guia de estilo do que uma metodologia rigorosa. Ele divide os estilos em várias categorias: Base, Layout, Módulo, Estado e Tema.

**Prós:**
* Modularidade: Encoraja a reutilização de estilos.
* Estrutura Claramente Definida: Organização clara do código.
* Flexibilidade: Não é uma metodologia rigorosa, oferece diretrizes.

**Contras:**
* Complexidade: Pode ser visto como complexo para projetos menores.
* Curva de Aprendizado: Requer familiarização com suas categorias.
* Possível Redundância: Pode haver alguma sobreposição entre categorias.

## 3. OOCSS (Object-Oriented CSS)

**Introdução:** 
OOCSS incentiva os desenvolvedores a pensar no CSS e no design da página como uma coleção de objetos: reutilizáveis, repetíveis e separados de seu contexto.

**Prós:**
* Reutilização: Promove a reutilização de código.
* Separação de Concerns: Separa estilos de estrutura dos estilos visuais.
* Performance: Menos redundância pode levar a arquivos CSS mais leves.

**Contras:**
* Abstração: Pode ser desafiador para iniciantes.
* Múltiplas Classes: Uso extensivo de várias classes pode parecer desordenado.
* Regras Estritas: Algumas regras podem ser muito restritivas.

Boa codificação!

## Para que serve

O package.json e o package-lock.json são arquivos cruciais em projetos Node.js. Eles servem para diferentes propósitos e são importantes para o gerenciamento de dependências e configuração do projeto.

* **package.json**:
* Metadados do Projeto: Contém informações básicas sobre o projeto, como nome, versão e descrição.
* Dependências: Lista todas as bibliotecas e pacotes de terceiros que o projeto depende.
* Scripts: Define comandos personalizados que podem ser executados no contexto do projeto.
* Configurações: Pode conter configurações para várias ferramentas e bibliotecas.

* **package-lock.json**:
* Snapshot Preciso: O package-lock.json fornece um "snapshot" exato das versões de todos os pacotes que foram instalados.
* Evita Problemas de Versão: Garante que todos instalem exatamente as mesmas versões dos pacotes.
* Otimização de Instalação: O package-lock.json permite que o npm instale pacotes de forma mais eficiente.

## Tree ou Árvore do Projeto:
├── app.js
├── combined.log
├── error.log
├── node_modules
── package-lock.json
├── package.json
├── public
│   ├── css
│   │   ├── 404.css
│   │   ├── admin.css
│   │   ├── economy.css
│   │   ├── index.css
│   │   ├── login.css
│   │   └── signup.css
│   ├── db
│   │   └── mydb.sql
│   ├── images
│   │   ├── logo.jpeg
│   │   └── me.ico
│   └── views
│       ├── 404.ejs
│       ├── admin.ejs
│       ├── economy.ejs
│       ├── forgotpass.ejs
│       ├── index.ejs
│       ├── login.ejs
│       ├── script.js
│       └── signup.ejs
├── readme.md
└── tools
    └── criadordehash.js