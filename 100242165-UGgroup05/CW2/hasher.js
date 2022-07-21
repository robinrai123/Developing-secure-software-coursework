function hash(str, seed = 0) {
    //basically does alot of stuff to generate a nice hash that's rare with collisions,
    //and has stuff like the avelanche effect.
    
    // ^ is bitwise XOR
    let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
    for (let i = 0, ch; i < str.length; i++)
    {
        //UTF code for each char, eg q is 113
        ch = str.charCodeAt(i);

        //imul multiplies two 32bit ints
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
};

function hasher(password, salt) {
    console.log("\ninput: " + password)
    console.log("input: " + salt)

    let input = password + salt;
    console.log(input);
    output = hash(input)
    console.log("output: " + output);
    return output;
}

hasher("password", "saltA")
hasher("password", "saltB")

hasher("passwordA", "salt")
hasher("passwordB", "salt")
