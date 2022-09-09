const Usuario = require('./usuarios-modelo');
const { InvalidArgumentError, InternalServerError } = require('../erros');
const jwt = require('jsonwebtoken')
const blck = require('../../redis/manipula-blacklist')

function criaTokenJWT(usuario){
  const payload = {
    id: usuario.id
  }

  const token = jwt.sign(payload, process.env.CHAVEJWT, {expiresIn: '15m'});
  return token
}

module.exports = {
  adiciona: async (req, res) => {
    const { nome, email, senha } = req.body;
    try {
      const usuario = new Usuario({
        nome,
        email
      });
      await usuario.adicionaSenha(senha)
      await usuario.adiciona();

      res.status(201).json(usuario);
    } catch (erro) {
      if (erro instanceof InvalidArgumentError) {
        res.status(422).json({ erro: erro.message });
      } else if (erro instanceof InternalServerError) {
        res.status(500).json({ erro: erro.message });
      } else {
        res.status(500).json({ erro: erro.message });
      }
    }
  },

  login: (req, res) => {
    const token = criaTokenJWT(req.user);
    res.set('Authorization', token)
    res.status(204).send();
  },

  logout: async (req, res) => {
    const token = req.token;
    try {
      await blacklist.adiciona(token);
      res.status(204).send()
    }catch(err) {
      res.status(500).json({ error: error.message})
    }
  },

  lista: async (req, res) => {
    const usuarios = await Usuario.lista();
    res.json(usuarios);
  },

  deleta: async (req, res) => {
    const usuario = await Usuario.buscaPorId(req.params.id);
    try {
      await usuario.deleta();
      res.status(200).send();
    } catch (erro) {
      res.status(500).json({ erro: erro });
    }
  }
};
