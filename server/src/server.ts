import AuthenticationHandler, { JwtClaim } from "./auth";
import express from "express";
import http from "http";
import socketio, { Socket } from "socket.io";
import EventEmitter from "events";

export default class TesseractServer extends EventEmitter {
    server: http.Server;
    app: express.Application;
    authhandler: AuthenticationHandler;
    io: socketio.Server;
    connections: Record<string, Socket>;

    constructor() {
        super();

        this.app = express();
        this.server = http.createServer(this.app);
        this.io = new socketio.Server(this.server);
        this.authhandler = new AuthenticationHandler();
        this.connections = {};

        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(express.json());

        this.app.get("/", (req, res) => {
            res
                .status(200)
                .redirect(
                    "https://icatcare.org/app/uploads/2018/07/Thinking-of-getting-a-cat.png"
                );
        });
        this.app.get("/api/authenticate", (req, res) =>
            this.authenticate(req, res)
        );
        this.app.get(`/api/checktoken`, (req, res) => this.checkToken(req, res));
        this.app.get(`/api/register`, (req, res) => this.register(req, res));

        this.io.on(`connection`, (socket) => {
            const handler = async (data: any) => {
                const { token } = <{ token: string }>data;
                if (!token) return;
                const claim = this.authhandler.validateToken(token);
                if (!claim) return socket.emit(`invalid token`);
                this.emit(`connection`, { claim, socket });
                socket.off(`login-request`, handler)
            }
            socket.on(`login-request`, handler);
        });

        this.on(`connection`, (data: { claim: JwtClaim; socket: Socket }) => {
            const { socket, claim: { username } } = data

            if (this.connections[username]) {
                this.connections[username].emit(`kicked`, { message: `You have logged in from somewhere else!` })
                this.connections[username].disconnect()
                delete this.connections[username]
            }

            this.connections[username] = socket

            socket.on(`file-request`, (data: any) => {
                // TODO
            })

            socket.emit(`welcome`)
        });
    }

    listen(port: number) {
        this.server.listen(port, "0.0.0.0", () =>
            console.log(`Listening on port ${port}`)
        );
    }

    async register(req: express.Request, res: express.Response) {
        const { username, password } = req.query as {
            username: string;
            password: string;
        };

        if (!username || !password) {
            return res
                .status(400)
                .send({ error: "username and password fields required." });
        }

        const success = await this.authhandler.register(username, password);
        return res.status(200).send({ success });
    }

    async authenticate(req: express.Request, res: express.Response) {
        const { username, password } = req.query as {
            username: string;
            password: string;
        };

        if (!username || !password) {
            return res
                .status(400)
                .send({ error: "username and password fields required." });
        }

        const token = await this.authhandler.authenticate(username, password);
        if (!token) {
            return res.status(400).send({ error: "invalid login" });
        }

        return res.status(200).send({ token });
    }

    async checkToken(req: express.Request, res: express.Response) {
        const { token } = req.query as { token: string };

        if (!token) {
            return res.status(400).send({ error: "'token' field required" });
        }

        const claim = await this.authhandler.validateToken(token);
        if (!claim) {
            return res.status(400).send({ error: "invalid token" });
        }

        return res.status(200).send(claim);
    }
}
