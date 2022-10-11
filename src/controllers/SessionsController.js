const knex = require("../database/knex");
const { compare } = require("bcryptjs");
const AppError = require("../utils/AppError");
const { sign } = require("jsonwebtoken");
const authConfig = require("../configs/auth");

class SessionsController {
  async create(req, res) {
    const { email, password } = req.body;
    
    console.log("{ email, password }", { email, password });

    const user = await knex("users").where({ email: email }).first();

    if (!user) {
      throw new AppError("E-mail e/ou senha incorreta.", 401);
    }

    const passwordMatched = await compare(password, user.password);

    if (!passwordMatched) {
      throw new AppError("E-mail e/ou senha incorreta.", 401);
    }

    const { secret, expiresIn } = authConfig.jwt;
    const token = sign({}, secret, {
      subject: String(user.id),
      expiresIn,
    });

    return res.status(201).json({ token, user });
  }
}

module.exports = SessionsController;
