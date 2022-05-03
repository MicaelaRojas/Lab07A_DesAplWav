import jwt from "jsonwebtoken";
import { secret } from "../../config";

// 👀 sign genera el token para el usuario
export const signToken = (payload) => {
  return jwt.sign(payload, secret);
};

export const verifyToken = (token) => {
  return jwt.verify(token, secret);
};

export const getToken = (authorization, res) => {
  if (!authorization) {
    return res.status(403).json({
      ok: false,
      data: "Usuario no Autorizada",
    });
  }

  if (!authorization.includes("Bearer")) {
    return res.status(403).json({
      ok: false,
      data: "Formato Invalido",
    });
  }

  return authorization.split(" ")[1];
};

export const checkToken = (req, res, next) => {
  const authorization = req.headers.authorization;

  const token = getToken(authorization, res);

  const decoded = verifyToken(token);

  if (!decoded) {
    return res.status(403).json({
      ok: false,
      data: "Token Invalido",
    });
  }

  req.decoded = decoded;
  next();
};