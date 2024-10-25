/*
 * Auto-generated by Frida. Please modify to match the signature of socket.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`socket(domain=${args[0]}, type=${args[1]}, protocol=${args[2]})`);
  },

  onLeave(log, retval, state) {
  }
});
