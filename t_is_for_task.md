## T is for Task: Uma Collaboration Tool
g.g.ashbrook 2024.09-12, 2025.11-12, 2026.4-5

Uma is a message and task-board focused distributed/decentralized platform.
1. Why do projects fail?
2. What are the skills needed to do team projects?
3. Can everyone learn project-skills?
4. Why does some software become obsolete and unmaintainable?
5. Can software-utilities be designed to endure?

Project-Status Dashboard:
Having all the parts is not equivalent to having project status and project status dashboard.


### Contents
1. Three Questions on Collaboration Tools

2. Introduction to Project-Tasks & 'Task-Boards'

3. Scope: Messages, Tasks. A Basic Outline of Features

4. Tutorial: Uma
- 't': tasks 
- 'm': message (modal, toggle view/insert with empty enter)
- 'move': Task on Board: 1. 'move' 2. What, 3. where, (done)
- 'add': task node


### Appendices
5. Process Design: project/product management and coordination more broadly
6. Software Design: moving parts and details
7. Prof. Skip Ellis and Project Neem
8. Future-Proofing: Long-Term Data Management & Long-Term Software Management
9. Defining Project Data
10. More Details on a 1960s Uma
11. Utility Case study: ex/vi/vim
12: Tiebreak: A case study of applications on a distributed platform using chess
13: Primitives & Future Forms
14. Links



# 1. Three Questions on Collaboration Tools:

1. Features: 
- What features are needed (to manage projects)? What User-Features/Functionalities are needed for a project to use best-practice satisfying the standards of (if not using all methods of) Agile and Kahneman-Tversky-Decisions for all main areas of project / product management?

2. Tools: 
- What tools are needed to effect what features? 

3. Timeline: 
- Could tools for Agile and Kahneman-Tversky-Decisions for project / product management have been built in the 1960's?


[These three questions are delicious. They cut through our imagined barriers between public sector, private sector, science and non-science, geography and culture, etc., and they challenge our understanding of the timelines of history on which we stumble. Regardless of whether anything else in this paper holds any use or interest for you, everyone should be enraptured with these questions and carry them however they will.]


# 2 Introduction: Tasks & 'Task-Boards'

Let's look at an example. 

Imagine you are working with a team, where you are all in the same workshop. And imagine, that where you have meetings, you are using an old-school-cool 1940's Toyota task-status-board. This means that you are using a physical board to share and see updates about what tasks people are working on, and how far along those tasks have gotten. You use the vertical columns of the board to share basic 'current-status' information such as 'this task is still being planned' or 'this task is now in progress,' or 'Done: this task has been completed.' On this 'task board,' you physically move something you are starting from 'Planning' to 'Started,' or something that you just finished from 'Started' to 'Done,' so that everyone else (including 'future-you') can see what the status is. For example, this could be moving a post-it note, or a magnet, or a cork-pinned slip of paper. And you also have, in your workshop, where you all work, blackboard or whiteboard note-boards for messages, notes, scribbles, taking polls, tallying votes, asking questions, etc. 

With these physical Task-Boards and Message-Boards, you and your teammates plan out your project, coordinate about the overall parts of the project, and the specifics of what is being done on tasks, and incorporate feedback from inside and outside the team to 'stay aligned' and make sure that everyone knows what the project is and what they are doing enough to follow through with completing the project. 

This is the specific user-story scope of features and functionality that Uma aims to cover.

At a high-level this is, or seems, simple. But easy things can be hard. There are many moving parts and details that usually make project-management non-trivial to follow-through on successfully. 

Hopefully adequate solutions for doing this already exist for some users (hopefully). The more detailed sections in the appendices below will look at use-cases and groups of users who likely are not currently being covered by available solutions (as of ~2025), and which use-cases and users Uma may be able to support. 

Before doing a final feature-overview and tutorial, let's look in a bit more detail at what is involved in task-definition and messages.


### Task-Board Actions:

We should have a concrete example of task-board use, so let's say that you and your friends are going to bake pizzas for a fundraiser and maybe as a summer business (if that works out). Because you are a botany major, you are in charge of growing the fresh basil. You have scrambled up a plan, and scrabbled up the pots, soil, and seeds, and you are now ready to start. So, to let the team know, you pop open the task board and move the 'Basil' task from 'Planning' to 'Started.' Sounds simple so far.

Let's look at this in terms of the actions a person takes. A simplified 'task-board-actions' list might look something like this: 

1. Orient: Make/Update your plan. Where are you now?
2. Communicate: Share your update using the Task-Board.
3. Align: Everyone else can see and sync with your update.
(Loop)

That still looks pretty simple. We should try to leverage that simplicity to keep the interface minimal: a well-focused and uncluttered task-board can be more practical. 


### Task-Boards as Process & Policy

Even where a set of actions is very simple (we can even use the more extremely minimal classic example of moving a bottle of water from one place to another), task-boards are doing some important things that happen less visibly.

One of the most important of these easy-to-overlook areas is perception, especially non-automatic perception: where we need to work-at and learn how to see something and actively maintain our ability to see it, or it disappears from our 'world' as with an extremely young child who loses all awareness of the existence of an object that they can no longer directly see. And 'object permanence' may be more than just an analogy here. 

Definition Behavior Studies is a more in-depth model and methodology that I strongly recommend for supporting this type of priority. The 'we can' statements outline a perhaps surprisingly large number of 'common sense' aspects of a project that sometimes we assume must be somehow happening in the background and take for granted that everyone agrees. But at other times, when the areas slip 'out of sight, out of mind,' projects go off the rails, perception fails, and discussion of (and alignment on) what failed becomes impossible. Invisible problems do not solve themselves or become visible automatically.
See: https://github.com/lineality/definition_behavior_studies 

A simplified set of policies and valued-processes for task-board use might look like this: 
1. Learning and Maintaining Non-Automatic Perception
2. Maintaining Sound Definitions and Agendas (Prevent System Collapse)
3. Not Repeating Past Mistakes
4. Communication & Externalization / Articulation
5. Feedback & Constructive Use of Data from Errors and Mistakes
6. Problem Solving
7. Iteration (Progressively-Incrementing Using Feedback/Repeating/Looping)


#### Non-Automatic Communication

Question: "Is all this detail really necessary? Doesn't communication 'just happen' as people work?" 

As I understand it, we can deliberately implement and maintain mechanisms for correction, but self correction is (and perception of, and skills in related areas, are) not automatic. History is full of examples where proverbial trainwrecks continue to snowball through decades of failure, often across multiple 'generations' of human lives. The kind of cross-reinforcing mechanisms and defaults that we hope and expect to support value function and meaning exist more on the other side: system collapse, and barriers to perception. 

Areas of STEM frequently appear shallow and trivial at first glance, but things that seem easy and simple often are deeper and tricker than our intuition would lead us to suspect. 

We should anticipate that teams eager to get started on a project under-estimate the underlying challenges of planning, communicating, aligning, and scheduling. But we should also anticipate that all participants can learn the basic concepts and skills needed for good-enough system-and-definition-hygiene (perhaps 'information hygiene') in the same way that all participants are entirely capable of learning and practicing health-and-medical hygiene.

For more, see: 
A study on tools for empirically analyzing specific communication skills and issues:
- https://github.com/stemnetbenchmarks/social_story_and_cookbook_puzzles 
An ongoing study of the parts and processes of coordinated-decisions:
- https://github.com/lineality/Networked_Voting_and_Decisions_Including_One_Time_Pads 


### Task Workflow with Policy/Values:

What the task-board is doing now looks not quite as simple as our minimal 'task-board-action-list' above. 

Updating and aligning happens in many areas. With each iteration, and during each step, many areas of updating, perception-adjustment, strategy and prediction-adjustment may be happening:
- Your perceptions and skills to perceive,
- Your plan, 
- The tasks on the board, 
- Your understanding of your and others' task(s) and how they relate,
- The schedule,
- Your own communications,
- Your skills and abilities: learning,
- Your understanding of aspects and implications of the project, 

(There are also all of the long-term, and soft-skills, and 'classroom management', parts of a team project space. Spaces can be growth filled, discovery-filled, exciting, productive, synergistic, positive environments, but they can also become (as the internet sometimes puts on display) fraudulent, toxic, bad-actor filled, disinformation-filled, nihilistic, hostile, zero-sum regressive, and dysfunctional.)


# 3. Scope: Let's do tasks. Let's post messages. 

At a high level, here are some of the main parts of Uma:

1. Tasks and Task-boards
2. Message-Posts
3. Modular Nodes, (like Lego-blocks)
4. Project-Areas


### T is for Task

Tasks are modular in Uma. By default you can start with a classic Kanban-Board style of organizing your project-tasks into the three "columns" of: 
1. 'planning' 2. 'started' or 3 'done,' but you are not restricted to that. You can arrange any 'Lego-block' configuration that you can think of. Each project can be different.

Task boards can be simple or elaborate and take many forms. For examples, see https://djaa.com/kanban-board-examples/ .  Being modular, Uma should be able to take, or construct, a variety of common forms. Extra features such as 'swimlanes,' for example, could be constructed by using a separate 'node' for each swim-lane, and viewing your choice of those together. This fits Uma naturally, since a 'swimlane' is basically a nested Kanban table (with several tasks) in one 'row,' a table made of tables. Task-nodes in Uma are inherently as nested as you want.


### M is for Message

If you and your teammates are all together in the workshop, then it is easy to formally and informally communicate verbally and with scribbled notes in myriad subtle ways. But when you are not in the same physical place, it is not automatically easy to facilitate all of that human language and body language if you are only sharing lines of text.

Uma needs to allow for flexibility in "messages and posts" and what they are intended to be for, so messages and posts in Uma are modular: not just messages, but building blocks of message-post systems. Sometimes you just want to instant-message someone. But sometimes the 'structure' around how you want to share posts is different. 

With a modular framework, you can 'Lego-Build' a large variety of message-post functionalities that teams may need the flexibility to perform: 

 1. Instant-messaging/text-messaging
 2. Micro-blogging
 3. Surveys
 4. Questionnaires
 5. Instructions
 6. Elections/votes/polls
 7. Suggestions
 8. Decision coordination
 9. Help channel (open or anonymous)
10. Feedback (open or anonymous)
11. 'Ticket' Request Systems
12. Standardized forms (as in filling in a form by entering data)
13. Quiz or test
14. Multiple choice
15. Write-in option
16. Mixed choice or write-in
17. Posts 'to the attention of' (ping-ing) a collaborator
18. Public Posts
19. Private Posts
20. Temporary Posts
21. Posts used to configure and use other applications, such as 'tie-break' (see below)
etc.


### Modular Task-Nodes

Uma is designed to be as modular as possible, so that most things are made of the same standard unit (like a lego-block) that can be placed in or next-to other building blocks. Each of these modular-units is called a "node."

The term "node" comes from the fact that Uma's teammate-shared-database is a particular type of database called (confusingly) a "graph" database. Here "graph" does not mean a chart or figure, but rather a type of data-structure made out of interconnected "nodes" (and the "edges" that connect them). 

Each node has message-post functionality.

Using the basic module-units in Uma (described here as "task-nodes," but you can call them whatever you want) it is easy to create and organize main and sub 'channels' or 'rooms' (or however you want to describe them), and to configure them for the functionality you need them to have: open, private, everyone, some people, ephemeral, encrypted, structured as questionnaires or votes/polls, etc.


### Project-Areas

There are six main areas where projects most often fall-apart and fail, and where projects done by the same institutions, teams, and individuals, will fail repeatedly for the same reasons while those reasons stay effectively invisible. These six Project Areas are a core part of tasks and nodes. When you make a new task-node, you are Q&A guided through each Project Area to add definitions to that task-node.

Even where elaborate software exists to plan and manage and track various parts of projects, these simple six failure-areas somehow manage to slip through the cracks and prevent projects from running smoothly while remaining off people's radar so those same mistakes recur indefinately. 

Another way to look at this situation of six main areas where most projects fail is to flip the portrait of a lack-of-skills upside down: projects done with skills and focus on these six areas have a much better chance of succeeding. Uma aims to help people to focus on aligning and communicating about these critical areas.

For a closer look at evaluating a narrow team-task coordination-skill-set (in the form of a team-game), see code and paper on Social-Story-Puzzles vs. Logistics-Puzzles:  
https://github.com/stemnetbenchmarks/social_story_and_cookbook_puzzles 


## Is vs. Is-Not

Uma aims to be a do-one-thing-well tool that should be able to:
- be set up
- run on devices
- have descent security standards
- allow teams to form
- allow teams to send messages
- allow teams to set up shared task-boards
- help teams to define and align on goals and project areas

Uma operates with no centralized server, subscriptions, or third party cloud services.

Uma is choice-based and ownership-based: You only connect with people who you actively agree to interact with. Every module of task-node and message-post is owned by someone.

##### DMCU-DGDB As Application Platform:
- As demonstrated by a basic 'tie-break' decision tool, Uma should be a modular distributed platform on which applications can be built (for example, customized for your current project) either inside or outside of Uma. 

#### Uma Is Not
There are a number of related functionalities that task management and messaging should not be confused with. Uma specifically is not designed to scope-creap into these features:
- not git
- not online file storage
- not general cloud file sharing
- not a general mass-storage sync tool/protocol
- not a project-documentation, reporting, publishing tool 
- not an office-suite
- not full project research planning, needs and goals analysis, post-production analysis, etc.

#### Uma Is
Uma aims to be a do-one-thing-well distributed-multipoint-conferencing-unit (d-MCU) and platform for type-strict task and message structures (not general data transfer) in the form of a distributed graph-database for project/product planning and management, alignment, and coordinated decisions.


## 4. Tutorial: Messages & Tasks in Uma
- Note: Uma's top-legend will tell you what the commands are.

### Walkthrough of Steps for Basic Uma Use

1. Launch Uma (in a command-line terminal)
- Type:
```bash
uma
```
- Press enter.


2. Pick a Team-Channel from the list
- Enter a number.
- Press enter.


3. Go to the Instant-Messenger:
- Type:
```bash
m
```
or
```bash
messages
```
- Press enter.


4. Type a message
- Press enter to toggle between 'messages-refresh' view and 'input text' modes.
- Type something:
```bash
Hi, Bob!
```
- Press enter.


5. Go back (leaving the message-post area) out to the main team-channel area.
- Type:
```bash
b
```
or
```bash
back
```
- Press enter.


6. Go to the Task-Board:
- Type:
```bash
t
```
or
```bash
tasks
```
- Press enter.


7. Move a task from 'Planning' to 'Started'
- Type:
```bash
move
```
- Which task (they are numbered) [do you want to move]?
- Type a number and press enter.
- Which column (they are numbered) [do you want to move it to]?
- Type a number and press enter.


8. Add a new task into the 'Planning' columns
- Go to the 'Planning' column: Type the number of the planning column (often '1') and press enter.
- Type:
```bash
add
```
- Follow the Q&A to define each part of that new Task "Node". This will include Project Areas, Custom-Message-Posts (if you want), and other settings (e.g. if you want the file to stay GPG-encrypted).

9. Go to the help-menu to read instructions about something.
- Type:
```bash
help
```
- Press enter.

10. Leave (Quit/Exit Uma)
- Type:
```bash
q
```
or
```bash
quit
```
- Press enter.


### Recap:
- Launch: 'uma'
- 'm'/'messages' 
- Toggle refresh-view / insert-message-text modes with empty enter
- Type a message and hit enter.
- 't'/'tasks' 
- Move Task on Board: 1. 'move'  2. What  3. Where
- Add task node: 'add'
- 'help'
- 'q'/'quit'
- Uma's top legend, and bottom info-bar, will tell you what the commands and options are.



### Setup & Configuration: Files and Wizards 
- See instructions on github: https://github.com/lineality/uma_productivity_collaboration_tool 

- Uma does not need to be 'installed' to run, it is a compiled executable file. Having Rust ('Cargo') installed will be useful, but is not required.

- First Setup: There is a setup-wizard to guide you with Q&A to set up your address-book file and your first team-channel

- Invite-Update Wizard: The 'invite' command will start a Q&A Wizard that will guide you through team-setup with team-mates and other configuration tasks. 

- Your files on your system: These helper-tools (which can no doubt can be further improved upon) are an optional convenience. Uma is a system of your files on your local computer system. There are no hidden-mysterious files in hidden-mysterious formats. There is no hidden-mysterious program-state. There is no hidden-mysterious software needed to make or read a file. Your project files are your plain text files on your system that you can look at, read, modify, encrypt, gpg-sign, OTP-envelope, etc. You can create or change those files with a text editor or any plain-text-file-tool you want. You can remove them any time by deleting them. 

## Links & References
- https://www.economist.com/business/2026/06/11/too-many-people-are-shockingly-bad-at-prioritisation 



## Appendices

# Design: How & What

Let's move our workplace example ahead in time beyond the 1940's. 

Moving ahead all the way to 1960s technology. Imagine that those task boards and message-post boards (that you all use to manage your project-areas) can now be shared between digital computers, so the team does not strictly need to be in the same physical workshop looking at the same physical boards. That would be kind of amazing.

But before we get too carried away, let's look a bit more closely at some of the details and moving-parts that are involved in using these seemingly-simple physical boards. As John McCarthy warned us, sometimes 'Easy things are hard.'

As with flute-making, a 'simple' physical analogue process (a physical tube or a physical task-board) does not always have a known simple mathematical description. 

1. What are the areas where people need to manage projects and manage alignment between team members and other parties? (What are 'Project Areas'?), 

2. What are the features needed to manage Project Areas, and what are the needs of different groups who need to manage project areas?

3. What are the tech-stacks and the tools (that you need for the features (that you need for the Project Area management (that you need to complete the projects)))? 

We can break this into two areas to outline:

1. Conceptual, Process & Policy (aspects of 'moving-parts and details')
- project/product management and coordination more broadly

2. Software Design (aspects of 'moving-parts and details')


## 5. Process Design
### Conceptual, Process & Policy aspects

Let's return a moment to the basic questions we began with:
1. Why do projects fail?
2. What are the skills needed to do projects?
3. Can everyone learn project skills?

In my experience and in my understanding of the literature and known data, projects of all kinds often fail, and computer-technology projects are especially prone to failure. While we may imagine or want to believe that the causes of project failures are exotic, unforeseeable, professional details:
- an unknown new disease outbreak
- a freak weather occurance
- a rare statistical anomaly
- a conspiracy
- a lack of high level achievement in a rare skill
- an accounting flaw so obscure that decades later people still can't figure it out

But the vast majority of the time, projects fail for very mundane, very consistent, reasons in about six categories. These mundane reasons are not exotic, and are well within the skill-range that virtually all 5th or 6th grade elementary school students could be highly proficient in these skills (if actually taught them). 

To recap: project-problem-spaces and coordinated-decisions on the whole can be non-trivial as STEM areas (and should be more invested in at a professional level). But most projects fail for entirely trivial mundane-level reasons in a small number of well known areas. The same problems happen over and over again in a kind of surreal wheel-of-samara, where it seems almost unbelievable that a species that considers itself extravagantly intelligent can be oblivious to these indefinately recurring lapses.

Why was the schedule missed? Because the schedule was deliberately not created, in a recurring act of short-sightedness.

Why was the user's need not met? Because the user was deliberately not consulted, in a recurring act of short-sightedness.

Why was the build goal not met for this ~two week period? 
A. Churn: Because the goal was deliberately 'churned' and suddenly changed to something else (often a dozen times), in a recurring act of short-sightedness.
B. Panic-Halt: Because the goal was deliberately halted in sudden panic, in a recurring act of short-sightedness.

Why did the interpretations of the goals by the team members drift further apart over time until they were no longer doing work that was either compatible with what other people were doing or that had anything to do with what the user needed? Because the scope-alignment was deliberately not done, in a recurring act of short-sightedness.

This is the level of mundane project area skills, the lack of which causes the same recurring issues across small, medium to large international public and private sector institutions, compounded by pride, institutional 'politics' (an unfortunate pejorative form of the term not representative of political philosophy overall), pecking-orders, habitual traditions, and a lack of leadership and ethics. And for probably ultimately biological reasons, because these patterns are so strongly universal and consistent over time and space, people are somehow indefinately oblivious to the fact that these same problems are happening over and over and over again. There is no innate, automatic project-level 'object permanence' in the human mind. At the same time, these literacies and skills can be very easily learned (much more easily than learning a new written language) by effectively all people. 

More abstractly, categories of processes (for coordinating about Tasks in projects) may look like this:
1. Communicate
2. Externalize/Articulate
3. Feedback
4. Learn and solve problems.
5. Do not repeat mistakes.
6. Iterate(Repeat/Loop)

While the focus of Uma aims to be deliberately constrained to a few highly structured modular-combinant 'task' and 'message' features, the dynamics of the system-space in which (and for which) this is happening should inform both the design and the use of tool-features. Specific areas of articulation and coordination are the scope we should focus on, especially the 'project areas' where mismanagement most often causes projects to fail.


The term "project areas" here refers to these specific ~Agile-project-management focused areas:

#### Project Areas:
1. Process (e.g. workflow type, policies, procedures)
2. Schedules (e.g. starting, stoping)
3. Users/Stakeholders (e.g. Who are they?)
4. Features, Needs & Goals (e.g. What are they?)
5. MVP (e.g. What is the first Minimum Viable Product to build?)
6. Feedback, Communication, Learning (e.g. using stakeholder feedback and identifying and acquiring needed skills)


### Balancing Deeper Details

There are a number of conceptual areas and skills areas around planning tasks, many of which can be quite in-depth.

We can, and perhaps for more subtle tool design should, go more deeply into details and areas around maintaining definitions and systems for projects, supporting decisions and coordinated decisions, and seeing how people might want to use message-post and task-board structures. 


For reference:

1. 'Task Boards' forms and uses
- https://en.wikipedia.org/wiki/Kanban_board 

2. Decisions, e.g.  
- https://en.wikipedia.org/wiki/Thinking,_Fast_and_Slow 
- Thinking Fast and Slow https://www.amazon.com/Thinking-Fast-Slow-Daniel-Kahneman/dp/0374533555 
- Noise https://www.amazon.com/Noise-Flaw-Human-Judgment/dp/B08LNYM39M/ 
- Nudge https://www.amazon.com/Nudge-Improving-Decisions-Health-Environment/dp/B097NJJ4PY/ 

3. Project management, product management, and agile
- https://github.com/lineality/project_areas_for_project_and_product_management 
- https://en.wikipedia.org/wiki/Agile_software_development 

4. Definition Behavior Studies 
- https://github.com/lineality/definition_behavior_studies 
(yet more details on project areas are here)

- A framework for modeling 'systems' such as teams, institutions, and projects, with a focus on temporal change in definitions.

- A framework for analyzing system-collapse (including project failures, planning failures, decision failures, and decision-coordination failures)

Filling out a 'Systems & Definitions Profile' for your team and for a given project is an example of something that Uma overtly refers to in the project areas (to *nudge users to at least comment on), but Uma has no (and perhaps to balance focus and scope uma should not have a) formal system for documenting in-depth system and definition details. Uma is not a full project documentation publishing and file storage system: the focus (to date) is task-status and message posts supporting alignment during "Agile"-type projects and tasks.

The above link is an essay-walk-through-narative of a step-framework-process that can be followed to model a given system in more depth, such as a project, team, stakeholder, user-story, etc.


5. Coordinated Decisions, Process, & Networks
- https://github.com/lineality/Networked_Voting_and_Decisions_Including_One_Time_Pads (more details on project areas are here as well)


6. Input-Output Measures (externalization/articulation)
- https://github.com/lineality/input_output_measures 


7 Needs & Goals Evaluations
- https://github.com/lineality/needs_goals_assessment_disambiguation 
- An equivalent of the questions at this link are recommended to disambiguate needs and goals analysis questions, which notoriously produce unhelpfully indeterminate answers. 


8. Project-Object Databases 
- https://github.com/lineality/object_relationship_spaces_ai_ml 
- For further depth if desired into topics such as externalization of project data and modeling project-spaces and system architectures designed to operate on project-object databases statefully, see Object Relationship Spaces, various sections of which are also available as separate Medium/Blog articles and github repositories.

*https://www.amazon.com/Nudge-Improving-Decisions-Health-Happiness/dp/014311526X 


This is just a starting set of examples. There are other clearly-relevant areas that are still too young to have clear conclusive models of, such as network design decisions. An example of such 'network design decisions' may be where the "designs" of parts of the internet have been clearly shown to be lacking or problematic, but where at the same time there is (very often) no clear consensus about what best-practice solutions, designs, and vetting are. 

Hopefully in the future there will be something more coherent than what we have in 2026 for:
- 'socially non-destructive networks,' and
- identity-authentication in networks, etc.

To strike a balance between task/message high-level coordination vs. project planning in more detail, Uma tries to focus on a scope that is as narrow, modular, and as clearly-definable as possible. Additional functionality can be added within Uma, on top of the Uma-platform-ecosystem, or separately on the side. Hopefully this modular approach is sufficient for allowing optional emphasis in directions called for per project, as projects and work-settings do often have unique needs. 


## 6. Software Design

### Three Questions on Collaboration Tools
1. What are the project-areas we need to manage?

2. Features: What User-Features/Functionalities are needed for a project to use best-practice satisfying the standards of (if not using all methods of) Agile Agile-Khaneman-Tversky-Decision Project-Product Management?

3. Tools: What tools are needed to affect what features? (E.g. In 2024 what if any tools could a non-clearweb business/ngo/institution/municipality/etc. use to effect 
Administration and productivity tools Agile Agile-Kahneman-Tversky-Decision best practice Project-Product Management? [GGA answer: None that I know of existed in 2024 (aside from early-alpha version Uma on github)])
(from https://github.com/lineality/definition_behavior_studies)

'Tools' like kanban-boards, local-election-offices, and surveys, are 'technologies' that have been developed over a few centuries and can be carried out more or less clearly with 'paper and pencil' tools. But for all the high-technology people have in  areas that are well developed (space travel, genetic engineering, etc.), digital-computer tools for project/project management and coordinated decisions are underdeveloped and under-invested-in (and our understanding of these areas is younger (and more nascent) than is often assumed). 


## Early Development
Uma is, as of 2025, still in early-development. The ideals for how it should be built are more exemplified by FF (it's file fantastic!) and the Lines Editor which use modules and new technologies developed in-house after Uma was started. Many of those modules and better designs have been integrated back into Uma, but there is still work to do. 

So far Uma has been largely an experiment to see what is possible: 
- Can we make a distributed Multi-Point Conferencing Unit (distributed/decentralized MCU) that does not use websites, web-logins, or any central servers at all? 
- Can users share gpg-clearsigned verifiable files with each-other?
- Can the software work in a Rust-Language space of strict data-types and strict-memory-management to improve long term maintainability and security? 
- Is it possible to have an optional 'Pad-Net' One-Time-Pad (OTP) layer in a packet-sharing network? 
- Is it possible to have the functionality of a graphic user interface (which is notoriously brittle, single-platform dependent, resource bloated, and not easy to modify, adapt, build-on, and modularize) in a Text User Interface that is robust, memory-slim, scalable, maintainable, modifiable, platform-independent, etc.?
- Is it possible to have stateless operations for viewing and interacting with (creating, changing) the shared-graph-database?

Hopefully this release of Uma is a viable, usable, MVP, and not merely an abstract proof of concept (POC). While Uma aims to stay minimal. There are doubtless useful or essential features that still need to be added, though some of these may be user and project specific suggesting that a core-uma should stay minimal and modular.  


#### Suite:
The overall goal is for Uma to be one of a set of inter-operable cli-compatible tools, and modules that can also have ~api functionality for other access and interfaces such a browser-GUI or TUI interface:
- Uma
- File-Manager/Explorer: FF
- Lines Editor: text/hex editor
- rows and columns/ csv-DB: dashboarding, reporting
- un-named: distributed data-science and IoT work
- un-named: raw-signal UDP
- GET-TUI: cli-compatible and Terminal-Compatible TUI web-pages / browser interface
- etc.


### Tools & Features Question: How to 'do' a shared task-board? 

The question of why a task-board does not somehow fit inside a simple shared text-doc or a .csv table (a spreadsheet) is very interesting. If someone told me (before I started working on Uma) that "companies used to use dedicated taskboards but now they use a shared .txt or .csv file to do the same thing with less overhead." I think that would have sounded feasible, almost expected. The puzzle of a 'shared' task-column-set structure (even without being nested) is one of those things that we casually assume must have a very, very, simple math-logic equivalent structure. For example, take the tiny example of just two columns: 'not-done' and 'done' and only one task: 'feed cat.' The non-John-McCarthy part of our brains deeply believes that this must be entirely simple, perhaps because we can visualize a mundane physical structure that performs this task (move a pin on a cork-board, move a post-it-note, or wipe and rewrite a whiteboard). But sometimes easy things are hard. As far as I know, there is no known way to use commonly available text-message and doc-link features (that most people know and use) to cover the functionality of even a basic task-board.

A task board is a strange kind of message board where the message does not change, but it moves in a N-dimensional space (more technically known as an "ecosystem," though that is likely counterintuitive-sounding since sadly people have incorrectly learned that the study of n-dimensional-hypervolumes is instead 'environmentalism'). A task board is simpler than instant-messages in some ways, as the language or sub-language symbols can be fixed, and terse. But the dimensionality of the space is elusive. 

A repeating theme here is that people underestimate project-task spaces and find them to be counter-intuitive (where following intuition keeps leading to failures and confusions). 

A task board can be simple. Personally, I think the minimal 'Trello' interface (a WEB-GUI for dragging and dropping tasks into columns) is brilliant and the most user-friendly that I have seen. Jira has so many features and functionalities for projects that arguably it is not really a Kanban-Board or even trying to be one, so much as a board-ish way of organizing myriad other features and functionalities. I recommend web-searching screenshots of Jira and Trello (both are now owned by Atlassian, Trello was purchased in 2017).

I want to try to separate criticism of education from criticism of Jira. I do think Jira's features are important to have for various roles in an organization, but predominantly where jira is used by developers on cross-functional teams during sprints I have seen Jira used both as a kind of blind cargo-cult of bureaucracy and as a 'you pretend to pay us, and we pretend to work' smoke-screen of obfuscation. In both cases incomprehensible webs of meaningless electronic form data are deliberately generated without any clear communication or coordination goals and zero intersection between that noise-creation and the practical-communication that is needed. A simpler similar analogy is the very real phenomenon of a 'standup' being very ironically misinterpreted as an obligatory in-the-weeds wordsalad session where people who are never guard-railed into learning what a standup is spend a half-hour flailing out miscellaneous project details: such a situation is clearly not a criticism of proper-standups; this should be an unambiguous situation that we can agree is a case where education and leadership are failing and the tendency towards mis-alignment is on full display.

The goal of uma is to try to focus on the scope of team-alignment, and to actively avoid wandering into features and functionalities that would detract from agile-alignment-communication. 


### Back to Time-Travel

Let's continue with our example of the team using 1940's technology and concepts (using physical boards and task-label-signs, hand-written message-posts, and in-person verbal chatting and updates). 

Let's keep moving ahead in time past the early-internet-years and imagine that you and your team can manage Task-Boards and Message-Posts without using websites, or subscription plans, or third-party accounts, or data-stored by host companies, or browsers, or touch-screens, or injection-ready legacy SQL systems, or even needing set up your own server in the cloud (or in a closet) to establish your network.


#### Selecting A Tech-Stack

For Uma's design: The only software, and data, is what is on each team-member's computers. The only databases are the synced-project-graph databases used by the team-members, which are human-readable files (if optionally encrypted) in directories on the users' computers. These files are to be used or converted in format how the user chooses to, with possible extra strictness in the team-channel setup.

For large organizations with large budgets, long timeframes, and many deployable employees, there are various existing services and service-providers to meet that niche of needs (that niche is not the focus here). Arguably makes the most sense for a particular large and profitable company to pay other specialist companies to support their IT infrastructure (e.g. where it can be demonstrated to save money in the long run by paying an expert to manage specific data and tasks, as in the case of specific Service-Now work that would be very costly to re-invent in-house). 

But not all common use-cases overlap with "Business-To-Buisness" services, web-subscription model services, or cloud-server infrastructure based services. 

For small teams, researchers, schools, students, and local-municiple type operations that broadly have less than no extra resources, there was until 2025 no viable option. Uma (however minimal and imperfect) is striving to be an option to cover some of the as-yet-orphaned niches and use-cases.

Part of the design process here is defining the process and policies, trying to understand how it is that project/product management and coordinated-decision software is not available for various ranges of users (including students, researchers, schools, libraries, first responders, municipalities, journalists, entrepreneurs, families, small institutions, etc.). 


#### For example:
- Current "standards and norms" of software design may be inadequate or incompatible with some user/stakeholder needs.

- Some groups of users and stakeholders may fall outside of key commercial markets that are able to fund an ecosystem of software.

- Task-Managers should have native support for messages, questions, discussions etc., but usually they are completely separate.

- Easy-Start services and dependencies can turn into later roadblocks where needed features (such as being able to access your own past data) is behind upgrade-paywalls that some sets of users cannot afford.

- Cloud login and web-security has become a troubled landscape without clear solutions, and security breaches at and through cloud providers is an ongoing problem.

- The economics of producing and maintaining software is still struggling for general paradigms. There is no mature market for software and services that incentivizes or allows for long term maintainable software. Even well-intentioned and broadly adopted products that are extremely popular and widely used in the short-term can be too costly to maintain in the long-term (such as visicalc and lotus-123). If you look at the software that the world is built on: posix, bash, c, apache-server, nginx, kubernetes, pypi, npm, etc. These are not for-profit packages, cloud-services, or subscription-based.

- Software such as Slack, Trello, Jira, and Service Now, can be just what is needed to enable productivity for the range of users who are able to use and pay for that product. And without that band-range of demand to allow for a market, the software companies that produce those solutions would not be able to afford to do the significant work of building and maintaining that software.

- Third party information sharing is either a liability, a risk, or not appropriate for a number of types of users, such as students or ethically/legally protected information such as healthcare and 'personally identifiable information' (PII) data. (While GDPR may be largely a separate topic, it might highlight some of the cases and edge cases where data-handling can become fraught.)

- ~Free options that are available for individual customers (perhaps including slack, zoom, and google-suite) may be no longer legal or appropriate if those same people are interacting as part of a municipality, or small business, or NPO, etc. and or the data-sharing environment may no longer be appropriate. 

There are many aspects of post-internet, post-DOS, software that are so common (in 2025) as to be assumed and presumed, but which are not necessary and in many cases may contribute to the lack of accessibility, the lack of maintainability, and the spiraling of costs and technical debt that IT projects usually exhibit.

Going to school on these design mistakes (or attempting to), Uma is designed to avoid and exclude the common costs and snags.

#### Uma is to have:
- no subscriptions or service fees (you run the software and compute)
- no third party information sharing (you store your data)
- no separate servers (uma runs on the device you are using)
- no load balancing backend or kubernetes devops
- no signing-certificate renewal
- no dns: configurations, updates, lookups, etc.
- no web-hosting/domain-configuration,etc. (uma is not website/server-bloatware)
- no service-hosting third-party companies
- no required api configurations
- no app-store tasks
- no website security liabilities (not a website application)
- no account-setup with a third party information-harvester
- no standard login email, password, passkey management (though GPG scope does exist)
- no liability of the service suddenly being turned off
- no middle-man barriers to accessing your own data
- no middle-man barriers to searching your own data
- no separate database setup or maintenance (e.g. no "SQL" costs, dependencies, security problems)
- no loss of access to source code
- no bottlenecks where a low-code/no-code solution becomes a roadblock


I have routinely seen it take a month+ to get a new employee added to a team's slack channel or jira account, with indefinately intermittent access interruptions that go on indefinately as webs of offices and departments gradually coordinate to fix issues. There is a kind of endemic learned-helplessness and external locus of control that dysfunctional software solutions are 'teaching' users. Too many students learn (and too many employees expect) that controls over, and success of, basic software is buried in Kafka-esk layers of bureaucracy that takes weeks, months, or years to churn and where 'competence' and 'status' means that you have a gang-post in a gate-keeper role in this tragedy of dysfunction, that security breaches are expected, that you will lose all your data, and that all of this will be ever-more expensive and require ever-more powerful hardware to do the same things (perhaps a "red-queen effect"). This is not how software tools are supposed to be. This is not how STEM ecosystems are supposed to operate. If it takes 6 months to make and show someone (somewhere in the same building) a single heatmap plot, people react with cynical complacency and embrace the inertia of a shake-down world when nothing works and no one can get anything done and no one should speak it about it or the nail that sticks up gets hammered down (as the Japanese saying sadly goes). This is not right. This is not where the timeline of STEM should be leading teams and institutions. This is not helping communities of participants.


# Diversity of Use-Cases

The stance here is meant to observe and account for a diversity of situations in a diverse world, certainly not to suggest a one-size-fits-all solution, and not to demean various areas and situations. While there are contextual criticisms and questions here related to commercial products, this is not meant to be a rhetorical position against software companies, software markets, or companies who want to pay for software. I am not anti-company, anti-intellectual property, anti-patent, anti-copyright, anti-regulation, anti-private-ownership, anti-investment, anti-market, anti-business, or anything along those lines, or 'anti' any general part of the world. Just as there is no 'single software package' for everything every company will ever need to do on any hardware, there should be a variety of solutions covering as many users and use-cases as possible. Students, researchers, libraries, municipalities, on-site healthcare and first responders, journalists, and others, may not always fit into a market of users for subscription services, be they consumer-directed services or designed specifically for large corporations who use a particular tech stack for particular operations and staffing. 

As of 2025, the current trend is to raise a firewall around students and minors to make it impossible for companies to interact with or store the information of students. How then are students going to train on and learn how to use project-management tools? A. They have no money. B. There is the 'regime uncertainty' risk that it could suddenly become illegal for companies to deal with that set of users, or that there would be an onerous and incoherent set of regulations as with GDPR data storage and permission requirements. Education and other areas often become a tragedy of the commons. A few children of wealthy well-connected parents will have rule-bending access to technology (as in the case of Bill Gates) and everyone else will have learned helplessness: that is not an education plan. 

From another approach, if companies do not want to (or would even be legally allowed to) voluntarily pay higher than necessary taxes so that municipalities can then re-route that tax revenue to pay for expensive software subscriptions, then there should be some open-source utilities out there.

As another example: 'Service Now' is a wonderful set of tools for managing many processes, if you are, or have the budget and staffing of, an international corporation or a state government, and can employ yet further consultants and engineers to help set up and use those services. If you are a third grader, or a single mother, or a forest ranger, or a researcher in Antarctica, or a student, or a small startup, or a normal public library, or a small-town doctor,  this is a complete mismatch:
- the cost is way out of range,
- the depth of the service is way beyond what you need.
If the European Union wanted to track every book-lending event in the entire EU over decades, and could dedicate a department with millions of Euros to spend to do this, then Service Now could be great for helping that to happen and run smoothly (and those data might in turn help the rest of the world and local library systems handedly). For the users/stakeholders who are the focus here, the best highest-quality Service Now software does them no good at all for their treehouse construction, or lemonade stand, or garage startup, or school maker-hackathon workshop, or local project getting the tires out of Mrs. Weatherdale's pond, or a small town hospital with a total staff of three trying to plan with an ambulance driver and a fireman across the valley. 

- https://www.economist.com/business/2026/06/10/fear-of-the-saaspocalypse-is-tormenting-techland 

### Practicality & Utility

Some processes have more or less translated sufficiently (if not so easily) into a digital form. Moving back and forth between a paper document and a digital document is, while not entirely perfect in all ways, good enough to work with in 2025 (and has been largely unchanged for years, for the most-part). 

Turning a paper notepad into a .txt file has worked very well (overall). And in some cases a .csv file and a spreadsheet can go a long way (though there is a bigger story there too). But it has been significantly more difficult to convert the physical process of moving a post-it-note on a shared whiteboard (or pinned note on a workshop cork board) so people can update the progress they are making and see how other team members are doing as well. 

Without getting conspiratorial, as Steve Gibson points out, there is a kind of flaw or perverse-incentive in the now perhaps extinct business model of producing software to be loaded and run locally: by making the software complete, the vendor has effectively put themselves out of business. To have continual income there needs to be some option such as:
1. a 'subscription' model where the user accesses a cloud service instead of running the software locally, and pays for it forever (ideally including IT help, updates, etc.)
2. a perpetual number of problems with the software that then requires customers to continually pay for new versions, technical support, patches, etc. 
or
3. embedded advertising
or
4. harvesting and monetizing customer data


And by looking at the evolution of software-vending as a business, the movement is clearly away from producing software that you pay for once and then use locally (which, before the internet, was the primary model).

Even in the early days of the Android operating system, many apps offered a one-and-done purchase option. And over and over I have had the experience of then being locked out of software that I had fully purchased (such as 'Auto-desk' image editing) because they retroactively changed to a monthly/annual subscription model. And, while frustrating, this makes sense: there is no clear business model in 'finished software.'

Again, this is not an anti-liberal-economics, pro-naive-musalini-fasciest-mercantilism message. There are certainly many contexts for private-sector development of software.

My intention is to point out that there are different categories of software, some should have advertising, some should utilize and monetize user input, some should be subscriptions, and some should be basic-low level open utilities. 

Look at the Unix operating system: The functioning world of software (dysfunctional software not included) runs on POSIX. If Bell-AT&T had succeeded in (for no apparent reason, just because they wanted POSIX to not be an open-utility) preventing anyone from using POSIX in the early 1990's, would the economies of today and the businesses of today be imaginable?  

When designing low-level and backup utilities designed to last a long time we should look at historical examples and think carefully about technology-maintainability, including both:
1. Long Term Software
2. Long Term Data Storage

Is it possible to design code that should be expected to still work, be maintainable, and be safe to use decades into the future? I think the answer is 'yes.' Assuming that a posix terminal will continue to exist, software that is designed to operate in that environment should continue to exist. While not all software has been well-maintained (ex-vi-vim is such a mixed-example) a large ecosystem of posix software has survived from the 1970's to the 2020's, including many utilities taken for granted. The DOS ecosystem is at least in some ways a counter example (though open-dos does exist), and should be examined to see how some software can lose support (or conversely how some platforms need support).

Long term data storage is a whole topic not explored in this paper, but likely of importance to many users and institutions. 


## Strategy & Simplicity 

How much simplicity are we aiming for? One lesson from the Dartmouth Internet is that there are some important nuances to networks and messages. Having a too naively simple and open system may be fine in the short-term for a small number of trusted professors or expert engineers, but once the system is open to either broader users and or bad actors, the design requirements for a working system start to look different. From memory-management and sound software to privacy and security (or data hygiene) oriented software, the bad-behavior and bad-security problems that became more clearly visible from the year 2000 were often in some form experienced during the timesharing-mini-internets of the 1960s. Sadly but predictably, when we did not incorporate feedback into the design process the result was repeating the same mistakes.

Is there such a thing as a declared abstract identity that functions sufficiently concretely? There may not be.

The approach that Uma takes is to be 'functional' as much as possible, with single-sources of truth, and functional sources of truth, not proliferations of declarations, abstractions, and reifications: 

- Your project is your shared project graph database.

- Your project graph database is/are your project files in directories on your digital computer.

- Your current team-channel is the base of your current path through your files, (not what something says that may be, or could or should be, or state-value passed along in a fragile myth of trust, not those, but the ultimately physical file-memory relationships on your device. When you visualize your project board in a TUI or GUI, you are seeing for convenience files in directories that you can interact with as your files in your directories.

- The current user is, ultimately, (access to) a shared gpg-key/id.

We want to keep the system as simple and modular as possible, but the design needs to fit the use-case and avoid known historical mistakes.


## Features, Functionality, Use-Contexts & Target-Users:

As much as possible future user needs, choices, and conditions should be anticipated (or attempted) such as future compilers (including LLVM-family) and the lifespan/lifecycle of libraries and software dependencies (or lack thereof). The thinking is that Rust compilers, POSIX-OS, and cli-terminal applications will be most enduring over time.

(Ideally there will be no 3rd party dependencies. As of 2026 walkdir,
rand, getifaddrs are used but will eventually be replaced with native safe vanilla Rust. Future LoRa-network functionality may (or may temporarily) use a 3rd party crate.)

#### Future-Proofing 1: Human, Hybrid, Swarm
While not a primary use-case in ~2026, there is a grey-area that starts with field-research on resource-constrained-devices (with modular configurability for automated tasks) and a hybrid field research-device-network with autonomous-devices (e.g. some form of AI-managed devices) that coordinate using the same network as people (e.g. weather sensors)). 

#### Future-Proofing 2: WAN, LoRa, etc.
The tool should be as flexible and modular as possible so that future changes to most-popular network and signal protocols can be adapted to easily. 
- https://en.wikipedia.org/wiki/LoRa 

##### Context:
- Features to support Coordinated Decisions for Projects
- Network Efficiency
- Network Security
- For Students 
- For Researchers
- For Municipal and Community Systems
- For Field Research with resource-constrained devices
- For Emergency Networks & Disaster-Response

- Uma for planning a decision/vote
- Uma for the logistics of a decision/vote
- Uma for data analysis on logistics
- Uma for data analysis of decision/choices/signals/votes
- Uma as an ecosystem of interactive modules, including those operating outside of uma itself: detached distributed platform applications.
- Uma's application layer

##### STEM & Project Specifics:
- Explicit Coordinated-Decisions emphasis
- Explicit Definition Behavior Studies emphasis
- Explicit Project-Areas emphasis
- Explicit needs and goals evaluation emphasis
- Explicit schedule management emphasis

##### Type of application:
- Source/compile oriented (e.g. to modify and re-compile easily)
- Long Term Maintainable 
- A Low-Level Open Utility that can be incorporated into projects as a module and modified/forked at a low level (not a high-level black-box subscription Entertainment-Service).
- Able to be integrated into your own project as a module
- Able to be directly modified, customized, or borrowed from
- Able to be understood at the code-level by anyone

##### Features/Functionality:
- Basic task-board functionality: move-able task in column
- Flexible-modular use of 'message-posts' for a variety of specific end-uses including poles and votes
- Describe/manage a task simply in one node
- Describe/manage nested-task (a hierarchy/DAG of nested tasks)
- Long-term archiving
- Facilitate search
- Facilitate project-diagnostics (e.g. schedule-dashboard)
- ~Cross-platform or platform agnostic
- Modular stateless functionality (e.g. call a specific operation such as read/write without loading excess state)
- POSIX compatible
- Headless OS compatible
- (future-goal, see 'lines editor') Power-of-10--2026 safety compliant
- Choice oriented
- Ownership oriented

##### Network-Flexible
- Low-bandwidth compatible
- Intermittent bandwidth compatible
- Network-agnostic
- Compatible with user needing to change type of connection
- WAN compatible
- LAN compatible
- ipv4 compatible
- ipv6 compatible
- No-DNS
- VPN Compatible
(future: native EM-spectrum use, e.g. LoRa compatible; audio-signal; optical-signal)

##### Security Notes:
- OTP Network Layer, One Time Pad (Optional)
- 'input' and 'output' to be defined strictly by Rust enums, structs, etc.
- gpg-ownership of file required to create, change, send, validate
- gpg-recipient-role-ownership required to receive a file
- choice to connect per participant-pair
- no raw plaintext project packet-content in transit
- strict input sanitizing: only Rust-structs are loaded & handled
- 'to-recipient' validation/verification
- 'from owner' validation/verification
- 'ower is sender' validation/verification
- replay-attack defense
- optional/configurable gpg-encryption of local files on disk
- goal to make use of Rust's features for safety
- etc.

##### Posix GPG Note:
A design decision was made to use the OS implementation of GPG rather than trust a third party quasi-implimentation or trying to re-impliment GPG, given the difficulty and level of testing that goes into posix GPG. In theory there are advantages to having a native-in-program handling of GPG, but there are also risks and disadvantages. While a theoretical future goal is to make Uma suitable for a micro-controler, that is currently too much scope. It is also not entirely clear that a super-micro version of Uma would not better reply upon One Time Pads rather than GPG (e.g. to reduce packet-size and overall application size).


### Value of Rust
A lesson that arguably has not been fully learned is that it is not simple to write safe production code.

Memory-management (often leading to security and other issues) is perennially assumed to be 'fine' and 'good enough' and then shown to be not good enough. Memory related security issues may be the most commonly discussed unintended side effect of memory management decisions but there are others such as, as described by Martin Kleppmann in "Designing Data-Intensive Applications", how garbage-collection itself is a standard interference and network-level-error introducing aspect of databases and networked software. As a distributed graph database, Uma not having garbage-collection may be an important design element.

See: https://www.amazon.com/Designing-Data-Intensive-Applications-Reliable-Maintainable/dp/1449373321 


### Early Development:
Uma is an experiment. As of 2026, Uma is more than a proof-of-concept or a demo, and more than a super-minimal MVP. The intended range of functionalities appear to be working. But it is neither battle-tested nor a multi-generational optimized-design.

It is not clear if it is the right modularity. It is not clear how the strict-owner and choice-strict model will work (socially, for productivity, for logistics). It is not clear how user-friendly the interface can be made to be (though there is a lot of flexibility with a browser-api-wrapper). It is not clear what optimal interfaces, wrappers, and APIs will be needed. But we should try. Having only one project-management-tool available to students is paltry and inadequate, but it is better than nothing.

As of 2026, Uma is still in a version-1 design. As Steve Gibson has described as "Built it; build it better; build it right." it generally takes at least three iterations of redesign and refactor (rebuilding from scratch) to arrive at an optimal structure. Work on File-Fantastic and the Lines-Editor represent examples of developing more-optimal standards and norms.

Uma has not been extensively tested yet (for example by professional cybersecurity testers), hopefully it will be. For the local tests that I have been able to do as one person working on the weekends, Uma is working. But surely in various real world situations there will be edge cases and needed-optimizations not yet covered by this early-version.


### Network Design: Efficiency, Resilience, Responsibility, and hygiene

An important aspect of the design of Uma is being ever more resource slim and efficient as fits the specific scope. "Maintainable," "resilient," "affordable," and "efficient" are goals. 

Packets (both content and requests) should be as small and infrequent as possible. 

Compare the cost, resilience, long term cost, and maintainability of the old pager/beeper system, with a messaging platform used by many companies in 2025, say, MS-Teams. How close could we get to the efficiency of pagers, while having the features needed?

It is a long term aim of Uma to be able to operate over EM frequencies such as CB-radio for emergency cases such as the 2011.3 Tsunami and Earthquake in Japan where mobile networks were disrupted. 

The question of how much you could tweak the Uma sync system to be faster to send more information is an interesting abstract question, but the real, practical, responsible, forward thinking, question is how sparse sync can be made to be and still work. The more sparse and terse a network protocol is, the more efficient, resilient, scalable, affordable, maintainable, and integrate-able it can be. 


## Ownership & Choice

Uma is also strictly 'ownership' based, which is something of an experimental departure from the ideology-driven abstract-object-reification-soup that has characterized software design presumptions for years, despite the ample evidence (since the 1960s) that anonymity and arbitrary access has been a serious network design problem and not a productive functional feature. 

Everything in Uma has an 'owner.' Everything in Uma is, while human readable in a 'toml' (labeled text doc) format, a type and size strict rust struct and gpg-clearsigned by the author/owner for verifying data integrity and authorship/ownership.


#### Orphan-Soup vs. Choice & Ownership
This more-strict system may either lack functionality or gain functionality, time will tell. A standard real-world problem of using confluence and Jira to manage projects is that the over-abstraction and over-flexibility make everything an anonymous Orphan-Soup that no one owns or cares about or has any incentive to care about: tragedy of the commons. Tasks are 'assigned' to people who never find out anything about the tasks, including that they were assigned. Descriptions and docs in a digital-commons end up being a hodgepodge of anonymous spam and redactions that nobody owns. Having projects and an internet that are 'commons' is theoretically exciting (to some people) and in reality a disaster. Having owned-tasks-by-choice and owned-comments is at least worth trying in earnest.




## 7. Prof. Skip Ellis and Project Neem
#### Neem & Uma

Part of my start in Data-Science, AI, and software development was under Professor Clarence 'Skip' Ellis at CU-Boulder. Professor Ellis was from Xerox Park and had a 'can-do' 'we should try' perspective. In the late 1990's and early 2000's he led the 'Neem' research project, which aimed to be a feature-rich team-collaboration assisting tool. The roots of Uma date directly to those 'Neem' years, down to the details of me precociously drilling him with questions about giving Neem a distributed MCU (instead of the default centralized conferencing unit). (Neem was an AI 'Agent' project back during an AI-Winter where the term 'AI' was taboo, so the term 'Agent' was the jargon of the day.) Neem was dreamt of as being an Agent-Based tool that could help teams with everything from project-logistics to cultural misunderstandings. In 2025, this probably sounds entirely feasible. In 2000, this was a far-out dream. But while Professor Ellis wanted fancy features such as real-time-video (something that Uma does not aim for) he also stressed the practicality and vast potential of elegant and simple technologies such as ELIZA-type interfaces. And since that time I have also seen many software models, services, and ecosystems turn into vapor-wear or become unusable over time. Some technologies are assets that last a long time, but others that are cheered as immortal sport favorites can suddenly become liabilities.

Uma is, or appears, in various ways to be minimal and old-fashioned, but that may be a trick of the light. Uma is designed to be robustly maintainable in such a way that it can make use of newer technologies, such as vector-embeddings, hybrid-databases (especially structure/unstructured databases) and generative foundation models. 


#### Flexibility of Use

The goal of Uma is to stay focused on a do-one-thing-well, small-ish-team collaboration use-case, and a very modular design. It takes a bit of design and under-the-hood 'feature' work to create a user-surface that is both simple and concrete. But the intention is that more work on Uma will make Uma more efficient, secure, maintainable, time-enduring, clear, and accessible. By analogy, look at the design and functionality of the Post-It-Note; it has a design that is flexible by virtue of its simple-modular design. It is probably impossible to count all the ways that teams and offices and households and boy-scouts and engineers have used Post-It-Nodes. A proper-simple design can leverage ever more uses. 

The basic modules of task-nodes and message-posts aim to move in this direction, not by spiraling into an ever-expanding array of high-level declared-features and 'functions' but by being functionally and concretely useful at a stable lower level, and by virtue of that being applicable to more areas, users, and disciplines. The more simply-defined the modules of Uma become, the more (like legos) they can be used in modular recombination to form a larger variety of more robust structures (almost like a programming language itself...sort of). Further development can and should increase efficiency, understandability, modify-ability, configure-ability, accessibility, etc. 

Low-code-no-code, high-convenience quick-start solutions notoriously lead to intractable situations of ever decreasing flexibility and compounding liabilities and costs. Too often more work on a set of tools becomes a vortex of abstractions that lead to less efficiency (more bloat), less compatibility, and less flexibility, not only more cumbersome for the user, but also so unmanageable by the engineers that they cannot be maintained anymore (so that either the company abandons the product or they go out of business). Both Visicalc and Lotus123 ruled the world for a few years as they started out as lean largely assembly-language built utilities, and both fell into scope-creap and abstraction chasing, and both went out of business in only a few years in a spiral of unmanageable technical debt. The amount of time needed to climb the next higher peak of abstraction and gimmickry was ever expanding, so that the 'next release' never came and the customers were all gone. The work-space of the spreadsheet has drifted over entire lifetimes and generations of people into a confused quagmire that people do not even recognize. Did data-science, machine learning, or deep learning AI come from using spreadsheet-software? These came from newer and lower level data-table software, not from the dead-end evolutionary boneyard of  GUI-spreadsheets. Yet the financial and psychological cost of fantasy-spreadsheets and "SQL" querying continues to be a spectacular cost and drain, fiercely defended by people who have lost all hope and who refuse to read anything like Arxiv submissions.

Scalability: Is there a looming cost that grows in hiding for an institution using Uma? If more teams, classrooms, offices, units, or squads, use Uma, is there any overall change in cost or maintainability? No. Is there a risk over time of plain text files not being accessible? No. Is there a risk that posix terminals will suddenly disappear? No. If you have access to Uma is there anything that can revoke your access? No. Is the need for the basic functionalities of shared Task-boards, project areas, and message-posts going to either disappear or transform into something else? On an overall scale of likelihood, these are unlikely. 



#### Compatibility-Flexibility, e.g. for Future Technology

For example: To a consumer who only sees the hype-fueled advertisements, a Super-Skip-Dream big-business audio-video-ai-multi-platoform-meeting-agent that spans across zoom, slack, MS-teams, jira, outlook, sharepoint, google-drive, etc., probably sounds easy for a big company to make. But the road map for that is very unclear and implementation would be costly, fragile, and most likely is simply impossible to produce in a rapid and high quality way (e.g. by the end of 2025). In 2035-2045, expensive and more limited and narrow versions for big companies in a particular ecosystem will probably be (maybe) generally available. On the other hand, connecting UMA to a local foundation model, a vector database, and a structured database, is shovel-ready. On a basic level, pointing a locally run model to query your project-database directory for a team-channel in Uma, including setting up prompts about project data, is already set up and very simple (this is a working application that I made and use: query-gguf
https://github.com/lineality/query_gguf_cli_rust_llamacpp 

Version-2 of Uma aims to have structured-data analysis of task schedule data as a built-in-feature. As Prof. Ellis emphasized: existing sound simple technology often works well; consider using it. 

(note: Georgi Gerganov's excellent llama.cpp api frequently changes so updates to any integration code will be needed: https://github.com/ggml-org/llama.cpp ). 

Something that people seem to have great difficulty with, both understandably at the margins and in other stranger ways, is separating known 'in hand' working technologies from 'possible future promise' software. Very often people 'want to believe' and assume a future technology will exist and be reliable. The vast majority of the time the future does not arrive.

With the super-multi-media-cloud-AI-system described above, it is unclear if or how you could start with many what-if hypotheticals. With Uma, you can make working prototypes in minutes and compare various approaches in a weekend, for effectively no cost and all on your project-computer. 


#### Future Needs & Future Skills: Articulation & Fitness

Prof. Skip Ellis had a way, either in a lecture or in the workshop/lab, of saying things very calmly and succinctly (often followed by a mischievous smile) that distilled years of careful analysis and observation. For example, he noted, that people tend to underestimate and miscalculate the work and resources needed to complete and maintain crucial parts of projects, resulting in those projects not being able to be built and used. (This discussion was specifically about building Multipoint Conferencing Units, so, as I gradually built up to trying to build (Neem 2.0) Uma's decentralized MCU, I made no presumption that it would be easy or even possible.)

Skip made observations such as this not with exasperation and not with resigned cynicism, but with the interested and caring recommendation of an optimistic parent or grandparent. He saw that it was a fascinating problem and that it was up to future generations to solve these problems (I did not realize it at the time, but within roughly a decade of these conversations he would very sadly pass away). Many parts of his conveyed observations, the insight, the calmness, the caring clarity, the way of communicating emphasis, are deeply rare to the point of being mysterious (a stark contrast with the clickbait hyperbole that suffocates communication in the 2020s).

At first I thought he was only referring to the part of the research that was being planned at the time (the MCU). Since then I have increasingly realized more, and more, of the scope of what he was describing. These were observations made by a Xerox Park veteran diagnosing critical (and invisible) challenges for an industry, a republic, a species, a planet of biology, a dusting of planets and stars.

The Dartmouth Internet did not survive, which was a serious loss of infrastructure investment and learning (as in the many cases where lessons were not learned). The Multics world failed at the beginning and never got off the ground, yet the shadow of network planning did not end there. The vast ecosystem of the DOS empire that reigned from ~1974 to ~2014, went from 'the only option for serious people' to a gone-forever yet still-proprietary enigma of the past (even chip-makers and firmware have to fake continuity with extinct-DOS to keep running).
- https://timesofindia.indiatimes.com/tech-news/16-37-users-still-run-windows-xp/articleshow/40867155.cms  (see ~2014 rough end date)
- https://en.wikipedia.org/wiki/FreeDOS  (see commercial need for workaround)

The DOS ecosystem both was not-fit to be a network-system and did not survive. This was a significant loss of investment in learning and infrastructure.

From the long smoldering ashes of Multix, an amazing community built POSIX, shells, and c, and the non-proprietary utilities of this software-design-pattern ecosystem has much better stood the test of time.

During the decades of deindustrialization from the 1960s repeated failures to solve problems and manage projects led to the erosion and destruction of town after town, city after city, region after region, across the planet leading to not just material loss and educational loss but such intense psychological suffering as to drive people in mass to regressive extremism in thoughts and actions leading yet again into the bad-equilibrium feared and fretted over by Thomas Hobbs‘s: the nightmare of neighbors harming neighbors, families harming families, and countries invading their neighbors.

The MIT Dartmouth Internet in the 1960s was not supposed to be followed by a repeat of the literal human slaughter of the 1930s, yet progression led in less than a century from the 1930s to the 2020s. We need to fix this, we need to study history, and we need to stop this from happening again.

We need to invest in and get serious about education and tool-infrastructure for the skills and best practices of managing projects. This is a general set of skills that can be fruitfully applied in many real world task areas: perhaps as a literal area of literacy, this is a fundamental tide that will raise all boats. And this is an area of non-automatic-learning where the default behaviors are elusively counterproductive.

I have been working on Neem/Uma (with huge gaps in the middle) over a period of nearly 25 years. If Skip had been over-stating his case, then areas that were difficult in 2002 should be easy-peasy in 2026, and the general infrastructure at the time (DOS-based windows) would be even more mature and solid after so many years of good-smart-human-quality-work. Contrariwise, progress on MCUs (and other general software and networks) during that time has been so glacial, non-existent, or collapsed and backward-moving, that (too often unable to match the patient humour of Skip) I am rolling back assumptions from around ~2000 about what languages, dependencies, platforms, and infrastructure, are suitable and reliable for Neem/Uma. 


## 8. Future-Proofing: Long-Term Data Management & Long-Term 
Software Management

When evaluating the use-case and context of a given software solution, two somewhat intersecting questions are: 
1. Should it be available in 4,8,16,32,64,+ years?
2. Will it be available in 4,8,16,32,64,+ years? 

In many cases software is only needed for one single use (non-production software) or for one short project, in which case it would be superfluous to consider multi-decade maintainability. In other cases it is unthinkable that they could ever not be available. 

For example standard POSIX epoch time values must be functional indefinately, so people have been working hard to head-off the 2038-rollover problem of a (bizarrely) signed 32bit integer timestamp designed to crash in 2038. This, even though the problem is more than ten years in the future (which is an almost miraculous rare example of people thinking and planning beyond a disposable short term horizon).

See: https://en.wikipedia.org/wiki/Year_2038_problem 

Of all the software services offered today, how many are expected or desired to be operating in 2038? (The grey area here would make for an interesting documentary.)

With an eye to the future, it is great to see more project-management type solutions, services, and options becoming available (from 'Monday' to 'Tasks' in google drive). Each project is different, and many projects can probably benefit from these services: and that is the goal, better availability and more use of project, product, productivity, and coordination tools across society in the private sector, public sector, and other areas. 

How many of these will be around in 4,8,16,32,64,+ years? How many should be? Uma is focused both on the use-cases of students and researchers (including in remote locations) and on the long-term-maintainability needs and extreme resource-constraints of municipalities, schools, libraries, etc. 

Potentially, both the most exciting and nervewracking of these tools is task/project management in google-drive. Google could probably provide more-democratically available basic and reliable tools to a very significant number of yet un-served users. And at the same time Google is profoundly fickle about supporting or maintaining their services. There is an entire wiki-pedia category (which is nested) on discontinued google services: https://en.wikipedia.org/wiki/Category:Discontinued_Google_services 

That this would both: 

1. most-likely enable billions of people around the world transforming lives and industries and then 

2. disappear entirely and without warning and without any easy replacement within a decade is nervewracking. As long as Google provides the service it makes no sense for competitors to make a destined-to-be-worse and more expensive alternative. And even after Google abandons it, the fact that the service could suddenly come back to life is a Sword of Damocles over any company that is thinking about investing in project management solutions (as tempting as the now unserved and expectant potential customer base may appear).

Again, I am not anti-Google in any way. I sincerely weigh that they are a good-faith company and have been very responsible and helpful to society (not all companies are so). I do not think Google should (or coherently could) be either compelled to support or to not support any given tool or platform (even though not being fickle about their own wearable platform does seem like common sense for their own self-interest). 

My aim here is to point out how this type of basic utility (task/project/product management) is a perhaps especially sticky-wicket trickly-pickle for software-design (it is not as obviously low level and universal as a posix-shell or a c-89 compiler, and not as obviously high-level-proprietary as industry-specific corporate finance software). It is as popular a root-canal, yet may be as important as public-santitation. There is no short-term win, and the long term necessity is sufficiently outside the popular attention-span as to make any advocate a popularly scapegoated pariah. 


## Slim & Modular vs. Simplistic & Limited
There may be a kind of inversion in people's impressions and expectations of software. People are pumped-up to believe in abstractions that then become prisons and liabilities. Huge amounts of time and attention are put into entirely frivolous graphics and 'feeling-ness' of an application. People fear operating at raw lower levels, and often erroneously believe that they cannot do so, but having the skills to do so lets people do more (and do so sustainably and maintainably). These are important challenges for education, psychology, and civics. 

Uma's ethos: be empowered; cut through illusions; follow STEM best practice; let bytes be your lego-blocks; focus on functionality; define your project area; identify and evade illusions and distractions.

- keep costs low
- keep overhead low
- coordinate more

Uma is a set of modular building blocks (which you can also easily further customize by going into the code itself and changing what you want). A 'Graph' is a kind of data-structure, or database, or data-tree, made of "nodes" and their connections to each-other. 

At least in a figurative way, a project is a sort of fractal web of nested tasks on different levels: 
- The team doing the project (and other projects) is maybe the top level of task-process. 
- The overall project itself is a task, at a high level.
- Both the management of the project and actually doing the project are webs of smaller or larger tasks (which may contain many other tasks, etc).

What if this figurative 'task' node were made more concrete? What characteristics should that node have?

Uma is a modular shared graph-node database where the basic unit of the 'graph (data-structure)' is a task, and each task has a dedicated message-post feature.

Many project-tools are both "mushy" and limited. Some tasks are inherently small, some are inherently larger, but most software takes a one-size-fits-all-socks approach that is needlessly cumbersome for a tiny-task and hopelessly limited for a large task-set. 

Each project and each local situation can have unique aspects that need to be adapted to. We have gotten a lot of mileage out of high-level word-processors (docs) and high-level spreadsheets, but (and most people will find this surprising) those tools are not the building blocks needed for basic coordinated decisions for carrying out and maintaining projects. As ubiquitous as word processors, spreadsheets, presentation slide decks, and instant-messenger programs have become, and as useful as they have been, by the 2020s, these tools are not (however counterintuitive this may be) sufficient or practical for the functionality of a simple physical Kanban-board, or for the Agile-ish project-area alignment that is fundamental for carrying out a project without collapse.

(Data is likely an important grey-area for future Uma scope (either features for a core-Uma or options tools to be in or with Uma). Legacy spreadsheets and SQL databases are a huge liability that Data-Science only came to exist by breaking away from: Data-Science and AI/ML did not emerge from and within SQL and spreadsheets. Even Python, which was instrumental in the formation and spread of Data-Science is (very consistent with the narrative here) a formidable liability and barrier when trying to mature academic production science into production-data science for real world use.

- https://www.youtube.com/watch?v=nOSxuaDgl3s (Jon Gjengset on Python vs. Rust for Data Science)
- https://www.youtube.com/watch?v=586_BAMMOQ8 (~43-min, Both discussion of the never-ending nightmare of python environment setup and management and an illustration of the also never ending "I heard this is a solved problem" perception.) 


## 9. Defining Project-Data

### Neem II:

How should data science connect with project management? 

While this is probably at least indirectly outside of the scope of Uma, how could or should analysis of data about past and current projects be used to help the people who are currently doing projects?

1. a topic-specific AI that might be able to advise team members on basic agile workflow, especially people just starting out. (Given that management advice can vary widely and often be empty rhetoric, this might be a tricky area. But with a narrow concrete focus this should be a reasonable goal, including having the model be small enough to run locally on common hardware. 

2. public data sets: with a combination of student teams and open-source contributions, it should be possible to assemble datasets about projects, as part of a larger project of understanding best practice.

3. schedule data is one area where data can be inherently 'structured' 

4. Uma is currently one step toward making project area definition, attention, alignment, and management more explicit, but it still leaves actions entirely up to the user. For example there is no overt way to track or visualize or monitor:
- defining categories of types of systems 
- doing and following up on a thorough needs and goals evaluation
- focusing on MVP scheduling
- getting feedback from users/stakeholders
- iteratively using feedback in all areas to fine tune or overhaul the next plan before moving ahead

But it is likely that even long time users will need to be nudged into basic processes such as getting feedback from users/stakeholders.

The design of the system sets up how accessible and how structured these data are for the users of the system to then put to their own analysis and uses. 

For more high-level simple-language walkthrough of how the distributed sync network works, see:
- https://github.com/lineality/uma_productivity_collaboration_tool/blob/main/docs/sync_network_overview.md 



## 10. More Details on a 1960s Uma & Agile Timeline
- Question: When should or could we have had basic collaboration and productivity tools developed, for example since the 1960s? 
- Question: Was such a tool available in the 1960s? (Could such a tool have been made in the 1960s?)

We need to make sure we do not put time-travel into this question.


### General Timeline Points:
- Dartmouth Time-Sharing System, version 1 - 1963-1966
- Kahneman & Tversky Collaboration starts - 1969
- Unix - 1969
- C - 1972
- TCP - 1974
- Diffie–Hellman key exchange - 1976
- BSD, ex-vi - 1978
- UDP - 1980
- Elliptic-curve cryptography - 1985
- Tomayko CS "Software Engineering Education" Proceedings - 1991 https://link.springer.com/book/10.1007/BFb0024280
- pgp - 1991 https://en.wikipedia.org/wiki/Pretty_Good_Privacy 
- gpg - 1999 https://en.wikipedia.org/wiki/GNU_Privacy_Guard
- Agile - ~2000
- 'The Power of 10' - 2006
- Daniel Kahneman Nobel - 2009
- Trello - 2011 
- Jira-Agile - 2012
- Rust memory safety - 2012


The question of whether a tool like Uma could have been (or perhaps was) available in the 1960's is a fascinatingly not-simple question. Technologically, I think we could have built a similar tool, and that we should have at least tried. But the 'soft' concepts of agile project management, network security, and production software standards, that we presume today (and which are still evolving today) were not mature in the 1960's. But how about a 1940's Toyota Board? Hmm... It is very difficult to say no. 

In the 1960's there were (I think) several timesharing 'mini-internet' networks (where a mainframe would be accessed by many terminals). MIT had a timesharing system. Dartmouth's timesharing was famously similar to the later broader internet in many ways (See: https://www.amazon.com/Peoples-History-Computing-United-States/dp/0674970977 ). And GE did have internal timesharing (see https://en.wikipedia.org/wiki/Dartmouth_Time-Sharing_System ) as well as providing the infrastructure to Dartmouth and others, and we could speculate (entirely speculation as far as I know) that they may have deployed some kind of project management system on their internal network.

We cannot expect overt-time travel where people in the past used processes, standards, or technical specifications that did not exist at the time. But we can ask if there was a well-known planning-coordination-utility for operating systems at the time, and for project management at the time, such as there were utilities for (forms of) "email" and "instant messaging". As far as I know the answer is no, but some of the 'early/pre' internet 'time sharing' systems existed in private companies such as General Electric (GE), who may have had their own internal tool not widely publicly known. One would think GE likely had some kind of project administration tools, and with Kanband boards being decades old even then, it is difficult not to push our present-day concepts back in time to force a "steam-engine-time" imperative onto them.

"A People's History of Computing in the United States" by Joy Lisi Rankin is an excellent book about this often unmentioned chapter in the history of both computer science and internet-type networks. See:  
- https://www.amazon.com/Peoples-History-Computing-United-States/dp/B07HHDFVHM/ 
- https://en.wikipedia.org/wiki/Dartmouth_Time-Sharing_System
- https://timereshared.com/ctss-dot-shell-email-chat/ 
- https://timereshared.com/ctss/ 
- https://www.cs.cornell.edu/wya/AcademicComputing/text/earlytimesharing.html 

Many industries and areas went into a tailspin from 1971. Maybe there were precursor systems that existed, or were started, that did not make it through the tumultuous years of changing software and hardware.

While it is almost hard to believe that there was not some kind of kanban-board-chat utility in the 1960s, one reason why it might have been unlikely that a project-management, project-coordination, decision-making, software-engineer-collaboration tool would have been created and used in the 1960s is that these were notably unpopular topics at the time. As I understand the timeline, long persistence by researchers and advocates has very slowly over the decades built up our current-day, still somewhat non-mainstream, appreciation for the importance of these. 

(System and definition behavior studies, and Coordinated Decisions in Network Processes, are my own research areas, so those were not available in the 1960's.) 

Daniel Kanaman himself (in "Thinking Fast and Slow") recounts that in the 1970's communication and coordination was strongly considered to not be part of software project management (catastrophically). And his own work on decision making in general was more or less persecuted throughout the 70's, 80's, 90's until he won a nobel prize for it. Tomoyako's report in 1991 shows that a lack of communication, coordination, project teamwork and project/product management skills were the critical bottleneck and missing skill-set in computer science professionally and in computer science education (perhaps this contributed to the slowly forming foundation for gradually establishing interest in and adoption of Agile project management). Aside from being astonishingly bare, the wikipedia page on Agile project management has no cited references before 2020; mentioning 2001 as the agile manifest publication date https://en.wikipedia.org/wiki/Agile_management. Needless to say, 2001 and 2020 are after the 60s, 70s, 80s, and 90s, and this lag is consistent with project management continuing to be not-prominant into the 2020's. Atlassian (founded (in Australia) in 2002) did not (according to wikipedia) branch into agile support until 2012). Again, in hindsight it is difficult to not impose 'current' expectations onto the past. 

Considering the extremely rapid and enthusiastic evolution of software from ~1950-1970, it is a puzzle how the evolution from 1970-2020 is so strikingly meandering, retrograde, plodding, and apathetic. 

The overall trend is that it is taking time for society to develop and accept concepts of general STEM, project and product management, and coordinated decisions etc. It is understandable, if disappointing, that team-coordination was not a priority in the 1960s. What is more frustrating is how slow progress has been, and how few of the lessons that (self-referencially) should have been learned-from to better project-plan the 1990's World Wide Web were not heeded. 


The main focus of this question, for me,  has two parts:

1. A basic team-alignment project-utility could have existed, in that the obstacle was conceptual and learning based, not a technological barrier; it is not as though some new form of processor, or memory, or peripheral devices (such as a USB-C port, or a wireless dongle, or advanced matrix/tensor parallel processing (e.g. GPU/TPU)) would have been required. 

2. In the interest of long-term maintainable software we should look at software and systems that can keep working (more or less) indefinately, because they focus on basic technologies and functionalities and avoid being dependent on ephemeral hardware or software that is only available for a short window of time. In particular, a command-line terminal application (or CLI compatible application) appears to be robust over time. Headless-posix terminal use and other uses are not mutually exclusive: This does not mean that the system cannot have another "api" or wrapper or other ways to use and interface with it.

We tend to be slow and resistant to becoming literate in new practices, however well supported by data they are. And then we tend to take current concepts that we had to be taught (that are not automatically part of awareness) for granted, missing how hard-won they were and how quickly they can be lost again. The psychology of learning is important for project/product management, decision coordination, system & definition maintainability, etc.


## 11. Software-Utility Case-Study: ex/vi/vim

As another kind of case-study, ex/vi/vim is a long-lasting application (sort of).

Vi may be a paradigmatic model of a basic available utility that the international community relies upon, from academia, to public sector, to private sector. The maintenance of such a fundamentally important core-utility is worth looking at more closely, and much of what we find will be less than ideal. 

While ex/vi is a case study of a terminal-based utility that has benefited people and software broadly simply by being available over a long period of time, the story of ex/vi is not a simplistic story of success to be directly emulated.

A. Use-Availability and basic maintainability are probably central, these appear to be what the ex-vi editor had enough of.
s
B. 'Open Source'/Available-Source took many decades. It is not clear if the original source code was lost, or how exactly the original ex/vi evolved into the available but somewhat troubled state it is in today.

C. Security: For me, one of the primary parts of the story of vim/vi/ex that has me most puzzled is something that I consider to be pertinent to long term software maintainability. As I monitor new software updates that come in, including security updates such as redhat, nist, CVE, and other known security and vulnerability warning and patches, I have for years been puzzled over the seemingly endless procession of (reported and fixed, so not including unreported or unfixed) security vulnerabilities in Vim including "Vim-Minimal" which has supposedly been feature-frozen since 1978 (Note: first dates for ex-vi vary between 1976 and 1978). How are there continually so many security problems with an extremely minimal utility that has had top-people working on it for generations, for longer than I have been alive?

https://www.cve.org/CVERecord/SearchResults?query=vim
e.g. https://linuxsecurity.com/news/security-vulnerabilities/vim-code-execution-vulnerability-linux 


One of the recent security issues, including vim-minimal, was with 'Wayland-Integration.' How does a 1978 terminal application have a GUI-Wayland (for graphics, not terminal-text) integration security vulnerability? 

This raises many topics about how a core utility should be available and maintained.
e.g. 
1. Should code be open for security testing? (yes)
2. Should a feature-frozen stable version be available for safe use (yes)
3. How important is the choice of programming language?
4. If an extremely minimal terminal application that has been used and refined for as long as anything can have been is still unmaintained and seems to be unmaintainable, what does that say about more derived and inherently less stable software? Is software development fundamentally more difficult than has been understood even by top professionals and academics? How many software developers are aware of the factors in long term software stability outside of their specialized work? 

1976-2002: ex/vi/vim was under legal restrictions while also being available, which is puzzling and unclear. (It was available but not open-source? Or available to use, but closed-source?)

2002-2025: Minimal vi continues to see a (never ending, never slowing) cascade of critical security vulnerabilities, which is puzzling and not ideal.


#### See:
- https://github.com/Cube9999/vi 
https://openhub.net/p/vi 
- https://pikuma.com/blog/origins-of-vim-text-editor
- https://openresearch.okstate.edu/server/api/core/bitstreams/9297c881-b145-4100-b574-b058a470464e/content 
- https://ex-vi.sourceforge.net/ 
- https://www.gnu.org/software/ed/manual/ed_manual.html 


Also see a related case-study in notepad++ (not to be confused with microsoft windows Notepad, though at the same time there was also a problem with microsoft-windows-notepad being broken by microsoft trying to integrate 'AI' into notepad):
- 'low level' video: https://www.youtube.com/watch?v=C8wKomo4Wds 
- https://notepad-plus-plus.org/news/hijacked-incident-info-update/
- https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/ 
- https://www.bleepingcomputer.com/news/security/notepad-plus-plus-update-feature-hijacked-by-chinese-state-hackers-for-months/
- https://techcrunch.com/2026/02/02/notepad-says-chinese-government-hackers-hijacked-its-software-updates-for-months/
- https://www.reuters.com/technology/popular-open-source-coding-application-targeted-chinese-linked-supply-chain-2026-02-02/ 


## 'The Power of 10"
In 2006, Gerard J. Holzmann with NASA published the now legendary paper 'The Power of 10' on the topic of best practice for sound production code, in the context of mission-critical C code for embedded systems for NASA. 

The impetus and points of Holzmann's paper should be used to spur the discussion and definition of expectations and standards both for specific software projects (in each narrow context) and for programming and system-programming more broadly. 

For example, while the original context of C for embedded systems will rarely directly map to a given software project, the topic around rules 5 & 8 for testing, catching, and handling 'errors,' exceptions, and assorted cases, will likely be highly relevant and important to align on indefinately. 


### See: 
- https://en.wikipedia.org/wiki/The_Power_of_10:_Rules_for_Developing_Safety-Critical_Code 
- https://spinroot.com/gerard/pdf/P10.pdf  
- https://spinroot.com/static/index.html  
- https://web.eecs.umich.edu/~imarkov/10rules.pdf


## Uma Timeline:
- Definition Behavior Studies Started 1997
- Distributed Contracts Started 1999
- Neem Meeting-Team-Support 2002
- Needs & Goals Evaluation System 2008
- Categories of Types of Systems 2010
- Disaster Relief Radio Networks 2011.3 (Dai-shinsai)
- Definition Behavior Studies 2012
- Input-Output Measures 2012
- Standard Learning Policies 2012
- Decentralized Protocols Started 2014
- CSV-DB 2020
- MAST - Stateless API Frameworks 2022
- Coordinated Decisions 2023
- POC-Uma: first proof of concept for Uma with distributed sync, 9-12 2024
- Clearsigned & .gpgtoml 2025
- File Fantastic (in-house TUI file explorer) 2025
- Query-GGUF 2025
- Rows & Columns 2025
- Full Lines Editor, TUI System 2025
- 'Power of Ten' Updated for System Programming 2025
- Source-It 2025
- Padnet-Uma 2025
- Alpha Version 1, Uma 12.2025


## 12: Tiebreak: A case study of applications on a distributed platform using chess

As one provided tool, and as one provided example of how a distributed multipoint conferencing unit based on a distributed Graph Database can be a platform for team-applications or distributed-tools, Uma has a 'Tie Break' functionality where team members who are split evenly on a decision can opt to decide the decision-match-point with a game of chess. 

The various features that make chess strange as a game make it both an excellent case-study for what is possible on a distributed platform and also useful as a Tiebreak mechanism, perhaps like the ever-mysterious president-of-the-senate.

Chess is:
- somewhat an interactive puzzle
- somewhat random
- somewhat turn-based
- somewhat non-turn-based
- somewhat rule-based
- somewhat arbitrary ad-hoc conventions
- somewhat systematic in instructions
- somewhat an unstructured hodgepodge of many 'dialects'
- somewhat civilized
- somewhat low-brow perennial barberous sport-dualing (which may make it easier for most people to accept using it)


Here are two reasons why it makes sense to at least try to have a chess-game within a coordination-tools platform:
1. as a possibly socially accepted mechanism for deciding a tie-break on a decision
2. as a case study to empirically evaluate how a variety of applications may or may not be able to be built in or on the platform.

#### 1/3rd Coin Flip, 2/3rds Mind-Brawl 
Chess is a highly noisy game, as is highlighted in much criticism of the ELO scoring system which penalizes chess players for random outcomes. I cannot find a specific published reference, but in the ~2024 debates over rates of cheating in online chess several people mentioned an analysis of chess.com data showing that lower-ranked players may win a particular game one third of the time. It may be difficult to put an exact number on this, but this trend is consistent across the body of chess practices. A classical chess match is not one game: Why not? Because you need more than one game to see beyond the noise. When there are competitions where every game is an elimination round, you see winners who you never heard of (and seldom hear of again). Etc. etc. While this is ponderous in terms of theories of chess play and the logistics of events, this may make chess an interesting candidate to be a tie-breaker mechanism: part coin flip, part skill-based challenge.


#### Where and With What?
Sometimes in computer science what you can and cannot do with a given architecture, tool, or data-structure can be misleading or counter-intuitive.

- Can you play a game of chess with someone over a text-messenger?
- Can you play a game of chess with someone in google-drive?
- Can you play a game of chess with someone in Jira (or in Service-Now/EverForth)?

Should you try or expect to do any of those?

If we look at the history of what we take for granted as being highly useful and effective now, there is often a Charles Fort 'steam engine time' timeline where in the early days of development the potential was not seen.

Would it make sense to try to play a game of chess inside of a coordination platform?
At first the unprecedented nature of the question probably suggests that that answer is obviously no (but what did Grace Hopper say about engrained norms of how things are usually done or not done? (she felt it was highly dangerous)). 

To turn the question round, might we instead need to justify not being able to play a game of chess within a project-coordination platform? Let's look at a version of that question focusing on Jira (selected because Jira is a very widely known and capable project management tool).

At first the question about playing chess in Jira may sound absurd: Jira is a project planning, tracking, management system for serious people with serious faces who wear suits and do serious things, not a childish game or entertainment-streaming service. But think about the technical details of the same question some more: Why exactly can't we play chess in Jira? Jira exists to not only plan out how to do a project but to track how and when every part of that project is done. Jira should be able to be used to plan and carry out and track every aspect of planning and carrying out a chess game. There seems to be a kind of invisible barrier here somewhere: Jira surely can do, it exists to do, each part of the question, but somehow knitting those pieces together does not happen. How can Jira be used to map and carry out every aspect of the game (who should do what, what's the status, is it done, who did it, etc.)... except Jira somehow cannot carry out and track the same game. That sounds like a kind of paradox, almost like the xeno-approach-paradox: we take every possible step but somehow never get there. This may or may not be a question that we can fully understand, as it may get more into 'stateful' projects than is currently known in STEM in 2026.

But what you can empirically demonstrate for yourself is that Uma can not only theoretically and abstractly support the parts of a chess-like team-project, Uma naturally supports a fully functional chess playing platform (and so, any platform-application, any project-syncing-application, with that class of features and requirements).


#### Does the chess application need to be 'inside'? (in the case of Uma, inside the binary-executible for the DGDB/DMCU (distributed graph database, distributed multipoint conferencing unit)? 
Overall, it does not. Both can work. Though there may be edge cases. If you wanted specific 'inside UMA encryption' to apply to various parts of the "game," then those would probably be best kept inside Uma. But any aspect that is not required to be secret can be 'externalized' for the tie-break application to see.
Here the example of chess and the context of private-data (or some private aspects of data) may help to trace out the problem-space where a distributed platform is an eco-system of applications that, based on context such as privacy, may have different parameters for how they can interact and where they can be. This may start to show how such an 'ant ecosystem' could scale without the same bottlenecks as centralized systems. 


#### Flexibility for Many Edge Cases
Chess is also a good example in this case for the various reasons that make chess an irregular and messy "game" (such as making or accepting draws, but not as part of a turn, or how third-time-repetition and fifty-move rules intersect with draws (and how repetition rules potentially introduce an unknown future limit of required memory-use and state).  For example if chess were more strictly turn-based, then barriers to entry would be lower and the requirements for flexibility would be lower.
There are various aspects of chess that are not simply turn based, such as draws. And draws are more the norm in chess, not a rare edge case that could be ignored to any degree. 

The modular system is an eco-system of interoperable parts of various kinds.


#### Tiebreak
It is difficult to predict if various groups of users will find a game-form tie-break to be acceptable or practical. Given that Uma takes choice-based workflow to perhaps an extreme, there may be more potential with Uma to confront and not 'of force' bypass areas where people need to actively-accept decisions and pathways to decisions. (An example or analogy may be when the madness of crowds and ignorance of history compel people to refuse to acknowledge the outcome of a transparently monitored election process (such extremism is not bound to any given group but like 'retisense to participate' itself is sadly universal).) Perhaps the act of participating in a tiebreak (as in other active choices to agree) will be useful for cultures of participation. It is unclear how the bane of Montequeue (people's unquenchable determination to settle (even imagined) differences through game-combat) might show itself in how people operate. How might a tie-break mechanism be used by people in the wild? It is very experimental, but I think it is a worthwhile experiment (speaking as a person who personally finds both the game and culture of chess to be overwhelmingly unfortunate). It is entirely possible that the 'game' of chess is too compromised and is simply junkfood for the worst short-circuits of biology, psychology, and mis-perception, but we should collect some data and base an evaluation of team-decision-games on data.

#### Empirical-Check on Scope
Another useful aspect of the chess example of a platform-application is to sanity-check how much work, or scope, an application needs to do. One of the great aspects of doing a chess-program project is that it challenges the persistently wrong intuition that 'Just a few logical rules surely won't require that much scope.' 

Also see papers on tiebreaks more abstractly, such as:
Axiomatic Theory of Tie-Breaking Impossibility, Characterization, and Decomposition by Frank M. V. Feys https://arxiv.org/abs/2605.22846 

#### Note: Second Binary Compilation
Because Tiebreak-Chess was designed to demonstrate a platform-ecosystem for applications, it is a separate 'program,' not inside Uma. To be able to use and run Tiebreak-Chess you will need to compile the memochess binary and put it in the same parent-directory as the uma binary.


## 14. Production-Rust Guidelines


Uma's future-proof ethos extends scope to include various aspects of how future-maintainable and safe code is. As a brief walkthrough of a larger topic, here are ~10 rules (and other commentary) for Rust in 2026, as a variation on NASA's 10 rules for embedded-c in 2006. The emphasis is on pointing out areas to be thoughtfully managed, more so than to dictate a one-size-fits-all way to manage each.

# 🦀 Rust rules 🦀:
- Always best practice.
- Always extensive doc strings: what the code is doing with project context
- Always clear comments.
- Always cargo tests (where possible).
- Never remove (still-current) documentation.
- Always clear, meaningful, unique names (e.g. variables, functions).
- Always absolute file paths.
- Always error handling.
- Never unsafe code.
- Never use unwrap (in production builds).

Theory and real life are completely different in production code.
Production code must be designed for bitflips, hardware failures, OS errors, etc.  Not pure platonic nirvana. 
E.g. According to Linus Torvalds, many or most windows blue screen of death issues in 1990-2010 happened because code did not account for real-world physical hard drive behaviors (including memory errors). According to Steve Gibson (and maybe Designing Data-Intensive Applications: by Martin Kleppmann) many network and database issues are caused by hard-radiation ("cosmic-ray") bitflips. 

Power failures happen. Hardware failures happen. Cyberattacks happen. Misbehaving applications happen. Rare edge cases happen. Race conditions happen. Undefined behavior happens. Most code does not have guardrails like either Rust or NASA's 'Power of Ten rules'. Etc.

Much code is only for R&D and internal one-off use, and that is fine. Printing 'hello world' to test should not require elaborate production-hardening. Not all code is or needs to be "production" code. But production code must be smart.

In production: Every line of code will fail eventually. Not 'if': every line of code will fail eventually. Production code is written to handle the failures when, (not 'if,' when) they happen. There is no 'should not fail.' There is no 'can not fail.' Every function will fail. Every call to every function will malfunction. Everything (in production) must be checked and handled so that when (not 'if,' when) these expected errors happen the process does not misbehave, crash, abort, or escalate malfunction, etc. 

Empirical processes are more "statistical," less tautological; and "statistical" quickly reaches into the unknown and the undefined. 

### Rules of Thumb (there will be exceptions and edge cases):

- Classic ~quote from Sid Meyer's Civilization Game: "The bureaucracy has expanded to meet the needs of the expanding bureaucracy." Bloat and project collapse due to nihilist mismanagement and bad project skills is not new to computer science. 

#### Rules Require Context:
- Rules such as 'Don't Repeat Yourself' or 'Separation of Concerns' require a context to be coherent and a compelling reason: Do not repeat yourself IF there is a compelling reason in a clear context. Does aerospace engineering have a blind policy of zero redundancy? No, it does not. Context matters.


#### Flat is better than nested. (Just like in the zen of python.)
- Always consider the flat option first.
- Be wary of ever-more nested structs that claim to infinitely 'separate concerns' for the sake of 'separating concerns.'


#### 'Get [what is] needed, when [it is] needed.':
- Do not load more into state than you need.
- Do not store more information than you need.
- Do not use more storage capacity than you need.
- Do not keep a hold/handle on a file longer than is needed (e.g. forever).


#### Grace Hopper ~"The most damaging phrase in the language is 'we've always done it this way.' The second most damaging is 'storage is cheap.'"
- Be as caring and vigilant about memory-economics as Grace Hopper (who famously walked around with a piece of wire 30 cm long — "a nanosecond" — to make engineers physically feel the cost of waste). Before suggesting the size for a variable (such as apathetically using more memory than is needed) imagine you are suggesting this to Grace Hopper to her face. Only use as much memory as you are absolutely required to use.

- Load what is needed when it is needed: Do not ever load a whole file or line, rarely load a whole anything. Increment and load only what is required pragmatically. Do not fill 'state' with anything that is not both necessary and actually used. Do not insecurity output information broadly in the case of production errors and exceptions (testing and debugging.

- Always use defensive best practice.

- Smoothly handle everything: Every part of every function will eventually fail, if only due to hardware failures or bit-flip noise (both of which are common in reality). As Linus Torvalds has explained, at the root of many 'blue screen of death' incessant window crashes in year's past were hardware irregularities that were not 'handled' by software. Production functions are not pure logic bubbles, they are physical engines that must account for all physically-possible (not just ideally-logically pure) outcomes. If a function gets a result from another function that is (for whatever reason, however logically impossible) malformed and broken, this needs to be handled, e.g. with the classic "let it fail and try again" resiliency model. Every return should be checked for what can be checked, with issues handled (structs and enums can be useful here to define what a healthy return value is allowed to be). 

Always error and exception handling: Every part of code, every process, function, and operation will fail at some point, if only because of cosmic-ray bit-flips (which are common), hardware failures, power-supply failures, adversarial attacks, etc. There must always be fail-safe error handling where production-release-build code handles issues and moves on without panic-crashing ever. Every failure must be handled smoothly: let it fail and move on. This does not mean that no function can return an error, nor does this mean that errors cannot be logged or reported. Case by case, a process can be retried or skipped, but the overall program must smoothly continue.

## "Do not stop" in production: Case Handling
Somehow there seems to be no clear vocabulary for 'Do not stop.' In production build code, when you come to something to handle, handle it:
- Handle and move on: Do not halt the program. 
- Handle and move on: Do not terminate the program.
- Handle and move on: Do not exit the program.
- Handle and move on: Do not crash the program.
- Handle and move on: Do not panic the program.
- Handle and move on: Do not coredump the program.
- Handle and move on: Do not finish the program.
- Handle and move on: Do not spiral into undefined behavior of the program.
- Handle and move on: Do not stop the program.

## Project-Level Context For Functions, Comments, & Doc-Strings
Comments and docs for functions and groups of functions must include project level information: To paraphrase Jack Welch, "The most dangerous thing in the world is a flawless operation that should never have been done in the first place." For projects, functions are not pure platonic abstractions; the project has a need that the function is or is not meeting. It happens constantly that a function does 'the wrong thing' well and so this 'bug' is never detected when functions are examined in isolation. Project-level (strategic level, architecture level) documentation and logic-level (tactical level) documentation are two different things that must both exist such that discrepancies must be identifiable; Project-level documentation, logic-level documentation, and the code, must align and align with user-needs, real conditions, the results of tests, and future conditions.

Safety, reliability, maintainability, fail-safe, communication-documentation, are the goals: not ideology, aesthetics, popularity, momentum-tradition, bad habits, convenience, nihilism, lazyness, lack of impulse control, cooties, etc. 

## No third party libraries (or very very strictly avoid third party libraries where possible).

## Scale: Code should be future-proof and scale well. The Y2K bug was not a wonderful feature, it was a horrendous mistake. Scale and size should be handled in a modular no-load way, not arbitrarily capped so that everything breaks.

## Power-of-10-style Rules of Thumb 
We can derive a list of '10 Rust Production Rules' updated for general systems programming in 2026 (derived) from NASA's 2006 'Power of 10' rules that were originally narrowly framed for c for embedded-systems.

These are ideals to be followed where possible and sensible, not absolute pedantic rules:

1. no unsafe stuff: 
- no recursion  
- no goto 
- no pointers 
- no preprocessor branching
(Term collision: Technically an 'unsafe code' block in Rust may be required for cases such as naked/assembly code or to interact with a Posix-OS, as in the case of raw-terminals. While use of jargon-'unsafe' blocks should be avoided where possible, the term 'unsafe' does not mean that a specific best-practice rule was violated.)

2. Loops: either firmly bounded or unbounded:
- Upper bound on all normal-loops (to make sure they do **not** keep looping)
- Failsafe for all always-loops to make sure they **do** keep looping (e.g. additional restart layer)

3. Pre-allocate all memory (no dynamic memory allocation)
- Production code should minimize or eliminate use of heap (e.g. very terse error messages that do not leak any user-data)
- Debug and testing often make sense to use heap and this code is not in production-binaries (e.g. detailed error messages)
- Clearly separate lazy-convension from real-need. With tools such as "Buffy'
github.com/lineality/buffy_stack_format_write_module, it is not necessary to use heap for string formatting.

4. Clear Function Scope and Data Ownership: 
Part of having a function be 'focused' means knowing if the function is in scope. Functions should be neither swiss-army-knife functions that do too many things, nor scope-less micro-functions that may be doing something that should not be done. Many functions should have a narrow focus and a short length, but definition of actual-project scope functionality must be explicit. Replacing one long clear in-scope function with 50 scope-agnostic generic sub-functions with no clear way of telling if they are in scope or how they interact (e.g. hidden indirect recursion) is dangerous. Rust's ownership and borrowing rules focus on Data ownership and hidden dependencies, making it even less appropriate to scatter borrowing and ownership over a spray of microfunctions purely for the ideology of turning every sub-operation into a microfunction just for the sake of doing so. (See more in rule 9.)

5. 'Case Handling' & Defensive Programming: debug-assert, test-assert, prod safely check & handle, not 'assert!' panic in production

Note: Terminology varies across "error" / "fail" / "exception" / "catch" / "case" et al. The standard terminology is 'error handling' but 'case handling' or 'issue handling' may be a more accurate description, especially where 'error' refers to the output when unable to handle a case (which becomes semantically paradoxical). The goal is that a program will not terminate / halt / end / shut down / stop, etc., or crash / fail / panick / coredump / do undefined-behavior, etc. when 'expected' cases occur. Here production and debugging/testing starkly diverge: during testing you **DO** want/need to see how (and where in the code) the program may 'fail' and where and when cases are encountered. In testing you need to stop with extensive details. In debugging you want to show extensive issue-details. But in production you need to never stop and you need to keep logs memory-terse and privacy-safe.
The proverbial satellite must never fall out of the sky, ever, regardless of how pedantically beautiful the error-message in the ball of flames may have been.

#### Six aspects of case-handlng (Rule 5 of revised 'power of 10' for Rust)
For production-release code:

1 of 6: Check and handle without stop/panic/halt in production

2 of 6: return result (such as Result<T, E>) and smoothly handle "errors" (not halt-panic stopping the application): no assert!() outside of test-only code
Return Result<T, E>, with case/error/exception handling, so long as that is caught somewhere. Only in cases where there is no way (or no where) to handle the error-output should the function always return OK(), failing completely silently (sometimes internal-to-function error logging is best). Allow-to-fail and handle is not the same as no-handling. This is case-by case.

3 of 6: test assert: use #[cfg(test)] assert!() to test production binaries (not in prod builds, not in debug builds)

4 of 6: debug assert: use debug_assert! with  #[cfg(all(debug_assertions, not(test)))] to run tests in debug builds (not in prod, not in test)

5 of 6: Note: #[cfg(debug_assertions)] and debug_assert! ARE active in test builds

6 of 6: Use defensive programming with recovery of all issues at all times
- use cargo tests
- use debug_asserts
- do not leave test-panic assertions in production code
- use no-panic error/case handling in production code
- use Option
- use enums and structs
- check bounds
- check returns
- note: a test-flagged assert can test a production release build (whereas debug_assert cannot); cargo test --release
```
#[cfg(test)]
assert!(
```

e.g.
# "Assert & Catch-Handle" 3-part System for organizing production behavior, debug behavior, and cargo-test behavior:

A three-part rule of thumb:

1 of 3: For Debug assertions: Only in debug builds, NOT in tests - use: #[cfg(all(debug_assertions, not(test)))]

2 of 3:. For Test assertions: use in test functions themselves, not in the function body (easy to conflict with debug/prod handling)
E.g.
When we run a cargo test:
- The #[cfg(test)] assert compiles and is active
- the cargo-test calls string_concat_list_function()
- an assert! in the abc_function (not in the test) panics immediately inside the abc_function
- abc_function never reaches the production error handling
- so abc_function never returns an Err(...)
- so the cargo-test 'fails' with a panic, not with a cargo-test error result

3 of 3:. Production catches: Always present, return production-safe no-heap terse errors (no panic, no open-ended data exfiltration), with unique error prefixes to identify the function, e.g. 'SCLF error: arg empty' for string_concat_list_function()


Note: Buffy may be useful in production error string formatting https://github.com/lineality/buffy_stack_format_write_module 

// template/example for check/assert format
//    =================================================
// // Debug-Assert, Test-Asset, Production-Catch-Handle
//    =================================================
// This is not included in production builds
// debug_assert: IS also active during test-builds
// use #[cfg(not(test))] to run in debug-build only: will panic
#[cfg(all(debug_assertions, not(test)))]
debug_assert!(
    INFOBAR_MESSAGE_BUFFER_SIZE > 0,
    "Info bar buffer must have non-zero capacity"
);

// this is included in debug builds AND in test builds
#[cfg(debug_assertions)]
{
xyz
}

// Production safe output example (Buffy is a no-heap alternative)
Err(_e) => {
    #[cfg(debug_assertions)]
    eprintln!("function-acronym: process-name: {}", _e);

    // safe log
    buffy_println!("function-acronym: process-name: failed", &[])?;
}

// Note: This is located only in cargo test functions.
// This is not included in production builds.
// assert: only when running cargo test: will panic
#[cfg(test)]
assert!(
    INFOBAR_MESSAGE_BUFFER_SIZE > 0,
    "Info bar buffer must have non-zero capacity"
);
// Catch & Handle without panic in production
// This IS included in production to safe-catch
if !INFOBAR_MESSAGE_BUFFER_SIZE == 0 {
    // state.set_info_bar_message("Config error");
    return Err(LinesError::GeneralAssertionCatchViolation(
        "zero buffer size error".into(),
    ));
}

Depending on the test, you may need a test-assert to be in a cargo-test function and not in the main function. 

Warning: Do not collide or mix up test-asserts and debug asserts, or forget that debug code also runs in test builds by default.; 
use #[cfg(all(debug_assertions, not(test)))] for debug build only (not test build).
use #[cfg(test)] assert!(  for test build only, not debug).
Give descriptive non-colliding names to cargo-tests and test sets.
            
Note: production-use characters and strings can be formatted, written, printed using modules such as Buffy
https://github.com/lineality/buffy_stack_format_write_module
instead of using standard Rust macros such as format! print! write! that use heap-memory. 

Note: Error messages must be unique per function (e.g. name of function (or abbreviation) in the error message). Colliding generic error messages that cannot be traced to a specific function are a significant liability. 


Avoid heap for error messages and for all things:
Is heap used for error messages because that is THE best way, the most secure, the most efficient, proper separation of debug testing vs. secure production code?
Or is heap used because of oversights and apathy: "it's future dev's problem, let's party."

We can use heap in debug/test builds only.

Production software must not insecurely output debug diagnostics.
Debug information must not be included in production builds: "developers accidentally left development code in the software" is a classic error (not a desired design spec) that routinely leads to security and other issues. That is NOT supposed to happen. It is not coherent to insist that open ended heap output 'must' or 'should' be in a production build.

This is central to the question about testing vs. a pedantic ban on conditional compilation; not putting full traceback insecurity into production code is not a different operational process logic tree for process operations. 

Just like with the pedantic "all loops being bounded" rule, there is a fundamental exception with conditional compilations: code that must NEVER be in production-builds must ALWAYS be excluded using conditional-compilation flags. This is not an OS or algo-tree conditional compilation, or a hardware conditional compilation; This is an 'unsafe-testing-only' vs. 'safe-production-code' condition. This includes several types of items, such as panic-inducing 'assert' statements (as opposed to proverbial-assert checks that do not panic-halt), and error-message data: Error messages and error outcomes in 'production' 'release' (real-use, not debug/testing) must not ever contain any information that could be a security vulnerability or attack surface. Failing to remove debugging inspection is a major category of security and hygiene problems.

Security: Error messages in production must NOT contain:
- File paths (can reveal system structure)
- File contents
- environment variables
- user, file, state, data
- pii data
- internal implementation details
- etc.

All debug-prints not for production must be tagged with:
```
#[cfg(debug_assertions)]
```

Production output following an error / exception / case must be managed and defined, not not open to whatever an api or OS-call wants to dump out.

6. Manage ownership and borrowing
- Rust is designed to greatly assist here (vs. c).

7. Manage return values: 
- use null-void return values 
- check non-void-null returns
- see above for designing and checking return values to handle cases of invalid other return-value cases.
- always have functions return a 'result' so errors and cases can be handled

8. Manage conditional compilation: Navigate debugging and testing on the one hand and not-dangerous conditional-compilation on the other hand:
- Here 'conditional compilation' is interpreted as significant changes to the overall 'tree' of operation depending on build settings/conditions, such as using different modules and basal functions. E.g. "GDPR compliance mode compilation"
- Any LLVM type compilation or build-flag will modify compilation details, but not the target tree logic of what the software does (arguably). 
- 2025+ "compilation" and "conditions" cannot be simplistically compared with single-architecture 1970 pdp-11-only C or similar embedded device compilation.

9. Communicate: 
- Use doc strings; use comments. 
- Document use-cases, edge-cases, and policies (These are project specific and cannot be telepathed from generic micro-function code. When a Mars satellite failed because one team used SI-metric units and another team did not, that problem could not have been detected by looking at, and auditing, any individual function in isolation without documentation. Breaking a process into innumerable undocumented micro-functions can make scope and policy impossible to track. To paraphrase Jack Welch: "The most dangerous thing in the world is a flawless operation that should never have been done in the first place.")
- Rather than using '?' for terse function calling, when possible have detailed error handling.
- Rather than having a result hidden in let _ =, allow that result to be shown in debugging

10. Use state-less operations when possible:
- a seemingly invisibly small increase in state often completely destroys projects
- expanding state destroys projects with unmaintainable over-reach


Also: As per Mara Bos's 'Rust Atomics and Locks' (O'Reilly) note the specific use-case and needs for threads, parallelism, concurrency, atomics, async, etc. Distributed processing varies significantly per project, and implementations of production functions, algorithms, and data structures, are rarely the same as abstract text-book examples.
🦀Vigilance🦀: Properly written code supports users, developers, and the people who depend upon maintainable software. Maintainable software supports the future for us all.
#### Links:
- https://en.wikipedia.org/wiki/The_Power_of_10:_Rules_for_Developing_Safety-Critical_Code
- https://spinroot.com/gerard/pdf/P10.pdf
- https://spinroot.com/static/index.html
- https://web.eecs.umich.edu/~imarkov/10rules.pdf
- https://www.youtube.com/watch?v=JWKadu0ks20
- https://en.wikipedia.org/wiki/Static_program_analysis
- https://www.oreilly.com/library/view/designing-data-intensive-applications/9781491903063/



## 13: Primitives & Future Forms
Even though electronic signal sending thought the early internet (from the history of message encryption though Turing's "Delilah" system, to Claude Shannon and telecommunications, to Time-Share to email to the WWW to 'social media') is scattered over probably more than a century, it is unclear what modes will be preferred and relied upon in future.

One example may be "email." From the vantage of 2026, 'email' infrastructure has become badly broken and is increasingly a liability while in various ways it remains a kind of fundamental building-block that many other systems rely on.


## 14. Other Links & Notes
- https://web.eecs.umich.edu/~imarkov/10rules.pdf: NASA: Rules for Developing Safety-Critical Code", Gerard J. Holzmann
- https://djaa.com/kanban-board-examples/ 
- https://github.com/Cube9999/vi 
- https://openhub.net/p/vi 
- https://pikuma.com/blog/origins-of-vim-text-editor
- https://openresearch.okstate.edu/server/api/core/bitstreams/9297c881-b145-4100-b574-b058a470464e/content 
- https://ex-vi.sourceforge.net/ 
- https://www.gnu.org/software/ed/manual/ed_manual.html 
- Tomayko CS "Software Engineering Education" Proceedings - 1991 https://link.springer.com/book/10.1007/BFb0024280, https://www.amazon.com/Software-Engineering-Education-Pennsylvania-Proceedings/dp/3540545026/ 
- https://en.wikipedia.org/wiki/Trello  
- https://en.wikipedia.org/wiki/Friden_Flexowriter 
- https://twit.tv/shows/security-now 
- grc.com/sn
- https://en.wikipedia.org/wiki/Trello 
- https://twit.tv/shows/security-now/episodes/1054 
- https://www.kings.cam.ac.uk/news/alan-turings-delilah-papers-saved-nation 
- https://en.wikipedia.org/wiki/LoRa 

- In Security-Now Episode 1054, there is an interesting anecdote about people still using an Apple IIGS for the music study software, and the technical details of what they may need to do to keep being able to access the physical floppy disk memory. 
https://twit.tv/shows/security-now/episodes/1054 
https://www.grc.com/sn/sn-1054.txt 
(And if this seems too remote, remember that large international companies are and will be indefinately scrambling to find hobbyist emulator kludges to fill the gap of DOS being made technically and legally inaccessible by microsoft.)

- Topic: Cost-Liabilities of Software and Software-Problems:
https://www.economist.com/business/2026/02/01/why-software-stocks-are-getting-pummelled 

- Example discussion of a case-study of an unfixed bug that inadvertently generates revenue https://www.youtube.com/watch?v=E3_95BZYIVs , illustrating both the classic incentive problem, and the psychological problems of people ignoring, defending, and embracing failure, and insufficiency, and bad behavior.

- otter.ai (example of similar-ish space of tools and features)


### Notes 
- According to the wikipedia on Rust, Rust creator Graydon Hoare '...described the language as "technology from the past come to save the future..."' 

- Uma, うま, is Japanese for horse.

