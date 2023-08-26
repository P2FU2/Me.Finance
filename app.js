/**
 * app.js
 * 
 * Este arquivo inicializa e configura um servidor Express para o aplicativo Me.Finance.
 * 
 * Funcionalidades Principais:
 * - Autenticação de usuários usando Passport, com armazenamento de sessão no MySQL.
 * - Registro de novos usuários com verificação de nome de usuário/e-mail existente e hashing de senha.
 * - Roteamento para páginas como login, administração e recuperação de senha.
 * - API externa para buscar dados de clima baseada na geolocalização do usuário.
 * - Middleware de segurança para proteção contra vulnerabilidades comuns da web.
 * - Logging detalhado de solicitações HTTP usando morgan.
 * 
 * Dependências Necessárias:
 * Execute os seguintes comandos para instalar todas as dependências necessárias:
 * npm init
 * npm install nodemon -g 
 * npm install express express-session mysql ejs passport passport-local bcryptjs path connect-flash axios helmet cors morgan dotenv
 */

// ======================== IMPORTAÇÃO DE MÓDULOS ========================
// Importação dos módulos e pacotes necessários para a configuração do servidor.

const express = require('express');                          // Framework web para criar o servidor
const router = express.Router();                            // Roteamento do Express para definir rotas
const mysql = require('mysql');                            // Cliente MySQL para conectar ao banco de dados
const session = require('express-session');               // Middleware de sessão para autenticação
const passport = require('passport');                           // Autenticação
const LocalStrategy = require('passport-local').Strategy;      // Estratégia de autenticação local
const bcrypt = require('bcryptjs');                           // Hashing para senhas
const path = require('path');                                // Manipulação de caminhos de arquivo
const flash = require('connect-flash');                     // Mensagens flash para erros de autenticação
const axios = require('axios');                            // Cliente HTTP para fazer requisições a APIs externas
const MySQLStore = require('express-mysql-session')(session);  // Armazenamento de sessão para MySQL
const cookieParser = require('cookie-parser');                // Analisador de cookies para manipular cookies de requisição
const nodemailer = require('nodemailer');                    // Módulo para enviar e-mails facilmente
const helmet = require('helmet');                           // Ajuda a proteger o app de algumas vulnerabilidades da web bem conhecidas
const cors = require('cors');                              // Middleware para habilitar CORS (Cross-Origin Resource Sharing)
const morgan = require('morgan');                         // Middleware de logging para solicitações HTTP
const winston = require('winston');                         // Para logging avançado
const validator = require('validator');                    // Utilitário para validações de string
const zxcvbn = require('zxcvbn');                         // Biblioteca para avaliar a força das senhas



// Carrega as variáveis de ambiente do arquivo .env
require('dotenv').config();

// Instanciação do servidor Express
const app = express();

// Definição da porta onde o servidor será executado
const port = 3000;

// Configuração do logger com winston
const logger = winston.createLogger({
  level: 'info',  // Nível de log padrão
  format: winston.format.combine(
    winston.format.colorize(), // Colorização do log para uma visualização mais fácil
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), // Adiciona uma timestamp ao log
    winston.format.printf(info => `${info.timestamp} ${info.level}: ${info.message}`), // Formatação personalizada
    winston.format.json()  // Formata o log em formato JSON
  ),
  defaultMeta: { service: 'Me.Finance' },  // Meta informações padrão que serão incluídas em cada log
  transports: [
    // Grava logs de erro em error.log
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    // Grava todos os logs em combined.log
    new winston.transports.File({ filename: 'combined.log' })
  ],
});

// Configuração de cores personalizadas para diferentes níveis de log
winston.addColors({
  error: 'red',
  warn: 'yellow',
  info: 'cyan',
  debug: 'green'
});

// Se o ambiente não for de produção, os logs também serão exibidos no console
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()  // Formato simples para a saída do console
  }));
}


// ======================== CONFIGURAÇÃO DO BANCO DE DADOS ========================
// Configuração da conexão com o banco de dados MySQL utilizando variáveis de ambiente
const dbConfig = {
  host: process.env.DB_HOST,      // Host do servidor MySQL
  user: process.env.DB_USER,      // Nome de usuário para a conexão
  password: process.env.DB_PASS,  // Senha para a conexão
  database: process.env.DB_NAME   // Nome do banco de dados a ser utilizado
};

// Criação de uma sessão de armazenamento usando a configuração do banco de dados
const sessionStore = new MySQLStore(dbConfig);

// Configuração do pool de conexões para o banco de dados MySQL
const pool = mysql.createPool({
  ...dbConfig,
  waitForConnections: true,       // O pool irá esperar por uma conexão se não houver conexões disponíveis
  connectionLimit: 10,            // Número máximo de conexões simultâneas
  queueLimit: 0,                  // Número máximo de conexões na fila (0 significa sem limite)
  acquireTimeout: 600000,          // Timeout (em milissegundos) para tentar se conectar ao banco de dados
  idleTimeoutMillis: 600000        // Timeout (em milissegundos) antes de uma conexão ser liberada se estiver inativa
});

// Evento disparado quando uma nova conexão é estabelecida com o banco de dados
pool.on('connection', connection => {
  logger.info('Conexão ao banco de dados estabelecida.');
});

// Evento disparado quando ocorre um erro na conexão com o banco de dados
pool.on('error', err => {
  // Verifica se o erro é devido à conexão perdida com o banco de dados
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    logger.error('Conexão com o banco de dados foi fechada.');
    // Tenta reconectar ao banco de dados
    return pool.getConnection(err => {
      if (err) logger.error('Erro ao reconectar ao banco de dados.', err);
      else logger.info('Reconectado ao banco de dados após desconexão.');
    });
  }
  // Registra erros não identificados
  logger.error(`Erro desconhecido do banco de dados: ${err.message}`);
});



// ======================== CONFIGURAÇÃO DO EJS ========================
// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public/views'));

/*
  // ======================== CONFIGURAÇÃO DO HELMET ========================

  // Configurando a Política de Segurança de Conteúdo (CSP) para permitir scripts da TradingView e outras origens necessárias.

  app.use(helmet({ // Proteção básica contra vulnerabilidades comuns
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            frameSrc: ["'self'"]
        }
    }
  }));

  // ======================== CONFIGURAÇÃO DO CORS ========================
  // Permite solicitações cross-origin de origens específicas. 
  // Adicione as URLs do frontend ou outras origens que precisam acessar o servidor.

  const allowedOrigins = ['/public'];  // Substitua por seu domínio frontend real
  app.use(cors({
    origin: function(origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        return callback(new Error('CORS policy violation'), false);
      }
      return callback(null, true);
    },
    credentials: true
  }));

*/

// ======================== MIDDLEWARES ========================
// Configuração dos middlewares para tratamento das requisições e respostas.

// Middleware para analisar o corpo das requisições POST
app.use(express.urlencoded({ extended: true }));

// Configuração e uso do middleware de sessão para autenticação
app.use(session({
  key: 'session_cookie_name',                          // Nome da chave do cookie de sessão
  secret: process.env.SESSION_SECRET,                  // Segredo usado para assinar o ID da sessão (armazenado em variáveis de ambiente)
  store: sessionStore,                                 // Define onde as sessões serão armazenadas (neste caso, no MySQL)
  resave: true,                                        // Força a sessão a ser salva novamente, mesmo se não foi modificada
  saveUninitialized: false,                            // Força uma sessão que é "não inicializada" a não ser salva no armazenamento
  cookie: {
    maxAge: 60000 * 60 * 24,                           // Define o tempo de vida do cookie de sessão (1 dia neste caso)
    httpOnly: true,                                    // Previne que o cookie seja acessado por scripts do lado do cliente (para segurança)
    // Para desenvolvimento, o 'secure' é falso. Para produção, descomente a linha abaixo.
    // secure: process.env.NODE_ENV === 'production'      
    secure: false
  }
}));

// Middleware para servir arquivos estáticos da pasta 'public'
// Isso permite que o servidor Express forneça arquivos como CSS, JavaScript, imagens, etc.
app.use(express.static('public'));


/**
 * Middleware para verificar se o usuário não está autenticado.
 * Se o usuário estiver autenticado, ele será redirecionado para a página de administração.
 * Caso contrário, o próximo middleware ou rota será chamado.
 */

function checkNotAuthenticated(req, res, next) {
  if (req.session.authenticated) return res.redirect('/admin');
  next();
}


/**
 * Rota para registrar um novo usuário.
 * Os detalhes do usuário são extraídos do corpo da requisição.
 * A senha do usuário é hasheada antes de ser armazenada no banco de dados.
 * Se o usuário for criado com sucesso, ele será redirecionado para a página de login.
 */

/**
 * Middleware para validar entradas do usuário durante o registro.
 * 
 * @param {Object} req - O objeto de requisição do Express.
 * @param {Object} res - O objeto de resposta do Express.
 * @param {Function} next - Função para chamar o próximo middleware ou roteiro.
 */

// Adicionando validação básica de entrada
function validateUserInput(req, res, next) {
  const { username, email, password } = req.body;

  // Verifica se o nome de usuário, o e-mail e a senha foram fornecidos
    if (!username || !email || !password) {
        logger.error("Campos de usuário faltando.");
        return res.status(400).send('Campos obrigatórios faltando.');
    }

  // Usa o módulo validator para verificar se o formato do e-mail é válido
  if (!validator.isEmail(email)) {
    logger.error("Formato de e-mail inválido.");
    return res.status(400).send('Formato de e-mail inválido.');
}

  // Usa o módulo zxcvbn para avaliar a força da senha
  const passwordStrength = zxcvbn(req.body.password);
  if (passwordStrength.score < 3) {  // zxcvbn retorna uma pontuação de 0 (fraca) a 4 (forte)
    logger.error("Senha fraca. Use uma combinação de letras, números e símbolos.");  // Registra o erro usando o logger
    return res.status(400).send('Senha fraca. Use uma combinação de letras, números e símbolos.');  // Responde com um status HTTP 400 e uma mensagem de erro
  }

  next();  // Chama o próximo middleware ou roteiro se todas as verificações passarem
}

// Inicializa o Passport para autenticação
app.use(passport.initialize());

// Usa as sessões do Passport para autenticação de usuários
app.use(passport.session());

// Define a pasta de arquivos estáticos (como CSS, JS, imagens) que serão servidos diretamente pelo Express
app.use(express.static(path.join(__dirname, 'public')));

// Usa o middleware de mensagens flash para mostrar mensagens temporárias (como erros de login) ao usuário
app.use(flash());

// Usa o middleware de análise de cookies para ler e escrever cookies
app.use(cookieParser());

// Usa o middleware morgan para registrar detalhes de todas as solicitações HTTP feitas ao servidor
app.use(morgan('combined'));

app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated();
  next();
});

// ======================== CONFIGURAÇÃO DO PASSPORT ========================
// Configuração da estratégia de autenticação local com o Passport e lógica de autenticação
passport.use(new LocalStrategy((username, password, done) => {
  const sql = 'SELECT id, username, pass, role FROM users WHERE username = ?';
  pool.query(sql, [username], (err, result) => {
    if (err) {
      logger.error(`Erro ao buscar usuário: ${err.message}`);
      return done(err);
    }
    if (result.length === 0) {
      logger.warn('Usuário não encontrado.');
      return done(null, false, { message: 'Usuário não encontrado.' });
    }

    const user = result[0];
    bcrypt.compare(password, user.pass, (err, res) => {
      if (res) {
        logger.info('Senha correta.');
        return done(null, user);
      } else {
        logger.warn('Senha incorreta.');
        return done(null, false, { message: 'Senha incorreta.' });
      }
    });
  });
}));


// Serialização do usuário para a sessão
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Desserialização do usuário da sessão
passport.deserializeUser((id, done) => {
  const sql = 'SELECT id, username, pass FROM users WHERE id = ?';
  pool.query(sql, [id], (err, result) => {
    if (result.length > 0) {
      logger.info(`Usuário desserializado: ${result[0].username}`);
      return done(null, result[0]);
    }
    else return done(new Error("Usuário não encontrado na desserialização"));
  });
});

// ======================== ROTAS ========================
// Definição das rotas para as páginas e funcionalidades específicas


function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.authenticated) {
    logger.info(`Usuário autenticado com o papel: ${req.session.role}`);
    
    if (req.session.role === 'admin') return next();
    else {
      logger.warn('Acesso negado para usuário não administrador.');
      return res.status(403).send('Acesso não permitido.');
    }
  }
  
  logger.warn('Usuário não autenticado.');
  res.redirect('/login');
}

// Rota para a página de administração, que é protegida pelo middleware ensureAuthenticated
app.get('/admin', ensureAuthenticated, (req, res) => {
  const data = {
    isAuthenticated: req.session.authenticated
  };
  res.render('admin', data);
});

// Rota para a página User Management
app.get('/admin/usermanagement', ensureAuthenticated, (req, res) => {
  
  // Exemplo: lista fictícia de usuários
  const users = [
    { id: 1, username: 'user1' },
    { id: 2, username: 'user2' }
  ];
  
  const data = {
      isAuthenticated: req.session.authenticated,
      users: users  // Adicione os usuários aqui
  };

  res.render('usermanagement', data);
});


// Rota para a página Reports
app.get('/admin/reports', ensureAuthenticated, (req, res) => {
  const data = {
      isAuthenticated: req.session.authenticated
  };
  res.render('reports', data);
});

// Rota para a página Settings
app.get('/admin/settings', ensureAuthenticated, (req, res) => {
  const data = {
      isAuthenticated: req.session.authenticated
  };
  res.render('settings', data);
});



// Rota para a página de economia
app.get('/economy', (req, res) => {
  const data = {
    isAuthenticated: req.session.authenticated
  };
  res.render('economy', data);
});

// Rota para a página de cadastro, que é protegida pelo middleware checkNotAuthenticated
app.get('/signup', checkNotAuthenticated, (req, res) => {
  const data = {
    isAuthenticated: req.session.authenticated
  };
  res.render('signup', data);
});

// Rota para a página de login, que é protegida pelo middleware checkNotAuthenticated
app.get('/login', checkNotAuthenticated, (req, res) => {
  const data = {
    isAuthenticated: req.session.authenticated
  };
  res.render('login', data);
});

// Rota para a página de recuperação de senha, protegida pelo middleware checkNotAuthenticated
app.get('/forgotpass', checkNotAuthenticated, (req, res) => {
  const data = {
    isAuthenticated: req.session.authenticated
  };
  res.render('forgotpass', data);
});

// Rota POST para registrar um novo usuário
app.post('/signup', validateUserInput, (req, res) => {
  const { username, email, password } = req.body;
  
  // Verifica se o nome de usuário ou e-mail já estão registrados
  const checkSql = 'SELECT id FROM users WHERE username = ? OR email = ?';
  pool.query(checkSql, [username, email], (err, result) => {
      if (err) {
          logger.error(`Erro ao verificar o banco de dados: ${err.message}`);
          return res.status(500).send('Erro interno do servidor.');
      }
      
      if (result.length > 0) {
          // Nome de usuário ou e-mail já estão em uso
          return res.status(400).send('Nome de usuário ou e-mail já estão em uso.');
      }
      
      // Hashea a senha
      bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
              logger.error(`Erro ao hashear a senha: ${err.message}`);
              return res.status(500).send('Erro interno do servidor.');
          }
          
          // Insere o novo usuário no banco de dados
          const insertSql = 'INSERT INTO users (username, email, pass) VALUES (?, ?, ?)';
          pool.query(insertSql, [username, email, hashedPassword], (err, result) => {
              if (err) {
                  logger.error(`Erro ao inserir novo usuário: ${err.message}`);
                  return res.status(500).send('Erro interno do servidor.');
              }
              
              // Redireciona para a página de login após o registro bem-sucedido
              res.redirect('/login');
          });
      });
  });
});


// Rota POST para autenticação de login
app.post('/login', 
  (req, res, next) => {
    console.log("Dados recebidos:", req.body);
    next();
  }, 
  passport.authenticate('local', {
    failureRedirect: '/login',
    failureFlash: true
  }),
  (req, res) => {
    // Após autenticação bem-sucedida, definimos variáveis na sessão.
    req.session.authenticated = true;
    
    // Suponhamos que o "role" esteja no objeto req.user. Se não estiver, ajuste conforme necessário.
    if (req.user && req.user.role) {
      req.session.role = req.user.role;
    } else {
      console.error("Erro: O objeto do usuário ou o papel do usuário não estão definidos após autenticação!");
    }
    
    res.redirect('/admin');
  }
);



// Rota para logout do usuário
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
      if (err) {
          // Se houver um erro ao destruir a sessão, você pode lidar com ele aqui.
          console.error("Erro ao destruir a sessão:", err);
          res.status(500).send("Erro interno do servidor");
      } else {
          // Redirecione para a página de login após o logout bem-sucedido
          res.redirect('/login');
      }
  });
});


// Rota principal do site
app.get('/', (req, res) => {
  const data = {
    isAuthenticated: req.session.authenticated
  };
  res.render('index', data);
});


// ======================== API DE CLIMA ==============================

const weatherApiKey = process.env.WEATHER_API_KEY;
const weatherBaseUrl = 'http://api.openweathermap.org/data/2.5/weather';

app.get('/weather-data', async (req, res) => {
  try {
    const lat = req.query.lat;
    const lon = req.query.lon;
    const weatherUrl = `${weatherBaseUrl}?lat=${lat}&lon=${lon}&appid=${weatherApiKey}`;
    const weatherRes = await axios.get(weatherUrl);
    res.json({
      city: weatherRes.data.name,
      weather: weatherRes.data
    });
  } catch (err) {
    logger.error(`Erro ao buscar dados do clima: ${err.message}`);
    res.status(500).send('Erro ao buscar dados do clima.');
  }
});


// ======================== MIDDLEWARE DE ERROS ========================
// Este middleware é responsável por capturar todas as requisições de Erros.

// Middleware para capturar 404 e encaminhar para o manipulador de erros
app.use((req, res, next) => {
  err.status = 404;
  res.status(404).render('404', { /* aqui você pode passar os dados que quiser para a view */ });
});



// Middleware para manipular todos os tipos de erros
app.use((err, req, res, next) => {
  res.status(err.status || 500);
  logger.error(`Erro: ${err.message}`);
  res.send(err.message || 'Algo deu errado!');
});

// ======================== INICIALIZAÇÃO DO SERVIDOR ========================
// Inicia o servidor na porta especificada.

app.listen(port, () => {
  logger.info(`Servidor rodando em http://localhost:${port}`);
});