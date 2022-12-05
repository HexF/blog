---
title: TUCTF2022 Generic Platformer Writeup
publish_date: 2022-12-05
---

Generic Platformer was a reverse engineering challenge part of TUCTF 2022. 
The application we are reversing is not a productive application, rather it is a game.

# Initial Analysis

Once looking through the files we are given, it is clear this is a game written with Unity, as by simply starting the game we are told "Made with Unity" before being dropped to the menu screen.

After a quick playthrough of the game, I noticed that there were 5 levels - Level 1, 2, 4, 5 and 6, missing Level 3.
I went on to investigate this missing level further, noticing that there were in fact 7 level files in the games data directory.
Figuring one was the title screen, I went on trying to work out how to inspect these files.

# Inspecting Levels

After noticing that Level 3 was missing, I needed to find a way to view all the level files.
I couldn't find any information on how Unity encodes its level files in the binary format I was observing, but I did notice some strings within the file, indicating that indeed the `level3` file, was a hidden level.

Instead of trying to open the file in some way that I could edit the file, I then looked to a way to loading it into the game, where I knew it would be loadable.
At this point I almost wanted to reverse engineer the code, but before I did, I had a better idea - just rename `level3`to `level1`. 
Doing this was successful, as upon starting the game and clicking "Start" I was dropped next to a bunch of tiles, with the bottom-most one looking like a `}`, indicating this was probably the flag.

The only slight issue I had was that I only could see a handful of characters when the character started falling, as we didn't start from the top. Thus, I had to find a way to move upwards to read the whole thing.

# Teleporting Upwards

To read out the entire flag, I needed a way to teleport upwards.
From here I pulled on knowledge back from my childhood days, getting inifinite money in Bloons Tower Defence using Cheat Engine.

Cheat Engine is a tool which attaches to a process and can analyze and modify the memory of this process.
Typically information such as your players world position will be stored in memory, and Cheat Engine allows you to filter through the entirety of the process's memory to find exactly what that memory address is.
It does this through a continuous refinement of searches, where you will start off with observing all the memory, and then will jump - changing the value in memory.
You will then tell cheat engine "the value I am looking for has increased" or "the value I am looking for has changed to **x**", and it will eliminate all those values which have not increased.
You repeat this process until you have homed in on a few memory addresses, then one by one can poke the values and see what changes.

I applied this exact same concept to the platformer game, slowly homing in on just 13 different memory addresses, which at that point I thought was safe enough to just modify them all.
After clicking back in the game, I found my self stuck in the air not falling.
I tried to move around and immediately started falling.
I then passed the entire flag, which went by too quickly for me to read out.


# Reading out the flag

Now that I could see the entire flag, the next step was to read it, but I was flying past it too fast to read out in real time, so I simply stared with a screen capture, then took the plunge down past the flag, recoding it.

Then with VLC I stepped through frame-by-frame reading characters out of the flag, until eventually I got it.


> Flag:
> TUCTF{JUMP_L1K3_MAR10_06031986}

And that friends, is how you do a rev challenge, without any rev.