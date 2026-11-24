"use client";

/*
  Firebase Authentication (email + password) for 3B. The browser signs in with Firebase, then sends the
  Firebase ID token once to the 3B backend, which verifies it and issues a normal 3B session. The role
  always comes from the 3B server, never from the browser.
*/
import { getApps, initializeApp } from "firebase/app";
import {
  createUserWithEmailAndPassword, getAuth, sendEmailVerification, sendPasswordResetEmail, signInWithEmailAndPassword, signOut,
} from "firebase/auth";

const config = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
};

export const firebaseConfigured = () => Boolean(config.apiKey && config.projectId);

function auth() {
  const app = getApps()[0] ?? initializeApp(config);
  return getAuth(app);
}

/** Friendly messages for the Firebase errors people actually hit. */
export function firebaseError(e: any): string {
  const code: string = e?.code || "";
  const map: Record<string, string> = {
    "auth/invalid-credential": "Wrong email or password.",
    "auth/wrong-password": "Wrong email or password.",
    "auth/user-not-found": "Wrong email or password.",
    "auth/email-already-in-use": "An account with this email already exists. Sign in instead.",
    "auth/weak-password": "Use a password of at least 6 characters.",
    "auth/invalid-email": "That email address doesn't look right.",
    "auth/too-many-requests": "Too many attempts. Wait a moment and try again.",
    "auth/operation-not-allowed": "Email sign-in is not switched on in the Firebase project yet.",
    "auth/configuration-not-found": "Email sign-in is not switched on in the Firebase project yet.",
    "auth/network-request-failed": "Can't reach Firebase. Check the internet connection.",
  };
  return map[code] || e?.message || "Firebase sign-in failed.";
}

export async function firebaseSignIn(email: string, password: string): Promise<string> {
  const cred = await signInWithEmailAndPassword(auth(), email, password);
  return cred.user.getIdToken();
}

export async function firebaseRegister(email: string, password: string): Promise<string> {
  const cred = await createUserWithEmailAndPassword(auth(), email, password);
  await sendEmailVerification(cred.user);
  return cred.user.getIdToken();
}

export const firebaseReset = (email: string) => sendPasswordResetEmail(auth(), email);
export const firebaseSignOut = () => (firebaseConfigured() ? signOut(auth()).catch(() => {}) : Promise.resolve());
