'use server'


export async function userAction() {
    return "You are not admin"
}

export async function adminAction() {
    return process.env.FLAG
}   