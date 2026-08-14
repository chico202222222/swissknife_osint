import { z } from "zod";

const schemas = {
    username: z.string().trim().regex(/^[A-Za-z0-9_.-]{1,50}$/),
    target: z.string().trim().regex(/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,252}$/),
    password: z.string().min(8).max(128),
};

const [username, target, password] = process.argv.slice(2);
const values = { username, target, password };
let hasErrors = false;

for (const [field, schema] of Object.entries(schemas)) {
    const result = schema.safeParse(values[field]);
    if (result.success) {
        console.log(`${field}: valido`);
    } else {
        hasErrors = true;
        console.error(`${field}: invalido`);
    }
}

process.exitCode = hasErrors ? 1 : 0;
