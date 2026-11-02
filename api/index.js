import { handleRequest } from '../dist/server.js';

export default async function handler(req, res) {
  return handleRequest(req, res);
}
