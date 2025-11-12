export const set = (name, value, expiry) => {
    let expires = "";
  
    if (expiry) {
      const date = new Date(expiry);
  
      expires = "; expires=" + date.toUTCString();
    }
  
    document.cookie = name + "=" + (value || "") + expires + "; path=/";
  };
  
  export const get = (name) => {
    let nameEQ = name + "=";
  
    const ca = document.cookie.split(";");
  
    for (var i = 0; i < ca.length; i++) {
      let c = ca[i];
  
      while (c.charAt(0) === " ") {
        c = c.substring(1, c.length);
      }
  
      if (c.indexOf(nameEQ) === 0) {
        return c.substring(nameEQ.length, c.length);
      }
    }
  
    return null;
  };
  
  export const erase = (name) => {
    document.cookie = name + "=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;";
  };
  