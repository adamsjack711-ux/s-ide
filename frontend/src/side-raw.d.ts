// Allow importing .side theme files as raw strings (Vite ?raw).
declare module "*.side?raw" {
  const content: string;
  export default content;
}
