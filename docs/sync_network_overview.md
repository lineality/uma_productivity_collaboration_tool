# Alice and Bob Collect Marbles: Intro
- (excerpt from ~full documentation for the Uma)

## User Story 1: Alice and Bob, at the office!
"Do one thing well, and pace yourself."

Imagine an office, a team office. if you will. In the office are meeting rooms. In each meeting room are two desks, one for each of two team-members or collaborators as we will call them. In this example we will only be looking at the desks of two collaborators: Alice and Bob.

Both Alice's desk and Bob's desk in this somewhat spacious meeting room have sitting on top a classic wireframe in-tray to put documents in. But, if less classically, there are two incandescent light bulbs, one to either side of that tray. On Alice's desk, in front of one bulb there is a sign that says: "I'm Ready, Bob." Inside the wire tray there is a sign that says, surprisingly, "In Tray (Things from Bob)." In front of the other bulb on the other side of the tray is a sign that says "I got it, Bob." Over on Bob's desk things look remarkably similar, except that the names on the sign refers to Alice: "I'm ready, Alice." "Things from Alice." and "I got it, Alice."



To review: Each pair of collaborators have a meeting room. In the meeting room are two desks. On each collaborator's desk there are three things. By using these three things the collaborators can be very clear about the steps of getting documents from the other person. 

There are also two other things in this meeting room: there are two marble dispensers: like wire shoots where you put marbles in the top, one by one they stack up. You can pull the next one from the bottom, over and over until it is empty like a classic gravity-feed dispenser. Each of these marble dispensers also has a sign under it. The one sign says: "Marbles for Alice." The other sign says, you guessed it, "Marbles for Bob." And yes, for the analogy, we will be putting marbles in the trays instead of pieces of paper.

The procedure or protocol works like this:
If the bulb by the "I'm ready," sign lights up, you take the next marble from the marble-queue-dispenser and put that marble in the tray. If the light by the "I got it." sign goes on, you can then carefully remove the marble from the tray and toss it out the window. But if the light by the "I got it," sign does not light up, then you need to try again (so don't lose that marble). If you wanted a second and the "I got it" light doesn't go on, you can grab the marble and push it back in the bottom of the dispenser and wait for the 'ready' light to sound again.

That's about it. 

This team is a marble-collecting-fan-club team, so everyone's job is to keep track of what kinds of marbles everyone else has collected. 

Alice was away volunteering for a local election the previous day, so when she starts work today, and joins the team, where Bob is her collaborator, she has a 'vacation-backlog' of things to catch up on. Bob has a few new marbles that she missed out on when she was away. 

So Alice comes in, after her day away, and, feeling ready, switches on the ready light. Bob, who was so busy preparing to add a new marble to his collection and did not see Alice come in, now sees the ready-light: Bob knows Alice is in the office and actively marbling away. Alice being here today, Bob checks his ledger and gets out all the marbles he hasn't told Alice about yet (all the ones from yesterday). 

Bob grabs the oldest marble and puts it in the in-tray. Alice notes it down in her records and turns on the "I got it!" light. Then, being ready for the next marble if there is one, she turns on the "I'm ready light again." Bob puts in the next marble. Alice notes it and hits the "I got it," light, and then the "I'm ready" light...and on and exactly the same way until Bob doesn't have anything new to show her. Now and then Alice turns the 'ready' light on to keep up during the day with anything new. And Bob does the same. Maybe Alice for her part found some marbles while she was off tallying poles, and now has to bring Bob up to speed as well. 

### To bring this analogy back to Uma: 
- The collaborator's marbles are their owned .toml files.
- The team-office is the team-channel.
- The items on the desks (the in tray and lights) and sets of 3-ports.
- The desks are threads.
- The 'I'm ready" light is either a timestamp or something like a json containing a timestamp. 
- The "I got it" light is probably a single 'zero' bit. 
- The in-tray is where you seen the next item in the send_queue.
- THe marble-dispenser is the list of .toml files you own that are timestamped AFTER the timestamp your collaborator just gave you.
- The meeting room is...a total fiction. Sorry, the meeting room isn't real.
- (See below: A Calendar)

## Three Desk Items + A Calendar
One item that was not super clear in the analogy is that the send-queue (the marble dispenser) is based on a ~shared timestamp. To extend the analogy, the marble-dispenser is next to a calendar on the wall, each marble has a date on it. There is a big X on the calendar and every marble in the dispenser (which is in chronological order from oldest at the bottom to youngest at the top) has a date AFTER the big x on the calendar. If Alice walks up to Bob's 'marbles for Alice' calendar and wipes off the big X and picks a different date...then Bob needs to re-do his marble dispenser so that the dispenser contains all (and only) the marbles dates after the X date. 





## In the code, see:
- fn you_love_the_sync_team_office()
