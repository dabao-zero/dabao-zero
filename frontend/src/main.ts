import "@fontsource-variable/figtree";
import "@fontsource-variable/familjen-grotesk";
import "@fontsource/ibm-plex-mono";
import "@fontsource-variable/caveat";
import "./app.css";
import { mount } from "svelte";
import App from "./App.svelte";

mount(App, { target: document.getElementById("app")! });
