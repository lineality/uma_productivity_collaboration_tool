### uma_productivity_collaboration_tool
```
4_|
/ \
```
"Read the old books."

## Tasks Boards & Messages Posts for Team-Channels
Uma aims to be a do-one-thing-well distributed-multipoint-conferencing-unit (d-MCU) for type-strict task and message structures in the form of a distributed graph-database for project/product planning and management, agile-like alignment, and coordinated decisions.
- Task-Board Functionality (modular)
- Message-Post Functionality (modular)
- cli
- TUI
- Distributed Multi-point Conferencing Unit 
- Distributed Graph Database
- RustY


## 1 ~Install
Uma is pre-compiled binary executable based. Your choices:
- A. compile locally yourself: install rust, build from git or local source (e.g. an online computer)
- B. compile or get binary-executible for the same type of hardware, then get that compiled binary executable, or if rust can be installed build from source offline (e.g. a lan-only computer that has no internet connection)

Be deliberate about where the executable is (do not flail through mysterious install procedures), and put it where you need it and use it how you need to use it. The 'Alias' method is recommended, easy to set up, easy to remove/undo/"uninstall". (see below)

## 2. setup-up
- when you run a particular binary-executible it will look to see (you can see them too) if there are configuration-setup files
- the first time you run Uma (or any time there is no local setup done) it will automatically start a Q&A-guide to set up A. local-owner-user and gpg B.team-channel-building. 

You can set up and use (at the same time) different instances of Uma as different binaries in different directories.

While uma tries to supply helpers and wizards, but you can make, update, and remove any file you want at any time. Uma is your files on your system.


## Tutorial: Messages & Tasks in Uma
- Note: Uma's top legend will tell you what the commands are.

1. Launch
- Type:
```bash
uma
```
- Press enter.

2. Pick a Team-Channel from the list
- Enter a number
- Press enter.

3. Go into the main 'Message-Post' area
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
- Press enter to toggle between 'messages-refresh' and 'input text' modes.
- Type something.
```bash
Hello World.
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

6. Go into the main Tasks area
- Type:
```bash
t
```
or
```bash
tasks
```
- Press enter.

6. Move a task from 'Planning' to 'In Progress'
- Type:
```bash
move
```
- Which task (they are numbered) do you want to move?
- Type a number and press enter.
- Which column (they are numbered) do you want to move it to?
- Type a number and press enter.


6. Add a new task into the  'Planning' columns
- Type the number of the planning column (often '1') and press enter.
- Type:
```bash
add
```
- Follow the Q&A to define each part of that new 'task' node. This will include Project Areas, Custom-Message-Posts (if you want), and other settings (e.g. if you want the file to say GPG-encrypted).

7. Go to the help-menu to read instructions about some area.
- Type:
```bash
help
```
- Press enter.

8. Exit Uma.
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
- In Message-Post browser: toggle refresh-view/insert-text modes with empty enter)
- 't'/'tasks' 
- Move Task on Board: 1. 'move' 2. What, 3. where, (done)
- Add task node: 'add'
- Quit/Exit Uma: 'q'/'quit'
- Uma's top legend, and bottom info-bar, will tell you what the commands and options are are.

## Setup & Configuration 
- See instructions on github: https://github.com/lineality/uma_productivity_collaboration_tool 
- First Setup: There is a setup-wizard to guide you with Q&A to set up your address-book file and your first team-channel
- Invite-Update Wizard: The 'invite' command will start a Q&A Wizard that will guide you through team-setup with team-mates and other configuration tasks. 
####  Your Files on your system: 
These helper-tools (which can no doubt can be further improved upon) are an optional convenience. Uma is a system of your files on your local computer system. There are no hidden mysterious files in hidden mysterious formats. There is no hidden mysterious program-state. There is no hidden mysterious software. Your project files are your files on your system. You can make or change those files with a text editor or any tool you want. You can re-sign them with the standard POSIX shell command:

```bash
gpg -r YOUR_KEY_ID --encrypt FILE_PATH
```
To manually view file:
```bash
gpg --decrypt FILE_PATH
```
If you don't want the additional security of gpg, then you choose during setup not to gpg-encrypt your own files.

It is all your choices about your files.



## Scope and Goals:
Uma's primary goal is to provide simple, secure, and decentralized collaboration tools for small (maker, build, and research) teams collaborating on projects.

Decentralized: No central server; each user runs their own instance of Uma and syncs directly with other collaborators.

Secure: Uses GPG for authentication and encryption to ensure data integrity and confidentiality. Each user owns and signs their own files, and chooses who they share files with.

Minimal: Focuses on essential team-administration features (instant messaging, task management, voting, etc.). This scope is not a replacement for git, google-drive, aws, etc. 

Modular: Designed to be easily adaptable and extensible for future uses, features, etc.

Accessible: Students, startups, and anyone with limited resources should still be able to have access to best-practice project alignment tools. 


### Six items for the use-case/context for Uma: 
- Aligned 
- Hygienic 
- Coordinated/Collaborative 
- Data-STEM 
- Productive 
- Projects
Uma is focused on this use-case specifically.
Not all activities include these characteristics.


# Best Practice
## Definition Behavior & System Collapse
## Tools for Project Management (non-collapsing projects)
- Alignments
- Scope
- Tasks
- Needs & Goals Definitions (not process reification illusion or goal reification illusion)
- Externalization



## Uma Collaboration Software 
- In memory of Eleanor Th. Vadala 1923-2023: aviator, astronomer, engineer, pioneer, leader, friend, ethical role model, good person.

- In memory of Walter Pergamenter: liberated from Auschwitz at the age of six after WWII; worked as an architect; a good person; taught me fundamental concepts of decentness and civility. 

- For Clarence 'Skip' Ellis whose project Neem (a team collaboration assistance agent-based project in the late 1990's early 2000's) was a foundational experience including Prof. Skip's insistence that the MCU portion of the software be considered with attention and not dismissed as a simple generic component.

- In praise of the still very much alive and working Steve Gibson of GRC and 'Security Now,' sharing sound advice and guidance for computer scientists.

- In respect of Amos Tversky and Daniel Kahneman, whose work on systems and information is pervasively important to many fields including computer science, the still nascent study of learning, and project management. 


# project uma:馬
"Read the old books."
- MIT license 
- https://github.com/lineality/uma_productivity_collaboration_tool 
- https://github.com/lineality/definition_behavior_studies
- https://github.com/lineality/Online_Voting_Using_One_Time_Pads
- https://github.com/lineality/object_relationship_spaces_ai_ml 

#### early pre-alpha development

## Topic/Context/Functionality:
- Productivity Software
- Collaboration Tools
- Task/Project Management (kanban, Agile)

## Uma:
- a Rust cli application
- Supporting researchers, developers, management, administration, and STEM
- Supporting projects, productivity, and collaboration.
- Supporting project-alignment (agile alignment), which is not-automatic and requires constant maintenance. 
- Supporting knowledge, education, learning, arts, speech, poetry, music, hygiene, language, and culture. ikezuki 池月: https://en.wikipedia.org/wiki/Ikezuki_(horse)
- Supporting boy-scout values.
- 馬さまたち、 頑張りましょう。


## Security
Different users will have different security needs and concerns, including how many steps they want or need to take to reduce their attack-surface. 


## Alias Method
The alias method is nice because you can keep your files wherever you want and still call 'Uma' from a terminal with whatever call-name you want. (It is also not exposed to being called as an installed program by other installed programs, which reduces attack-surface.)

Put your executable-binary somewhere, and associate that path
with a callable keyword for your command line interface (CLI)
so that entering that keyword calls the executable (starts the program):

1. Make or get the binary executable and put it somewhere: e.g.
```path
/home/YOURCOMPUTERNAME/uma_tools/uma
```
2. Open the bash shell configuration file in a text editor. The configuration file is usually located at ~/.bashrc or ~/.bash_profile. (use whatever editor: vim, nano, hx (helix), gedit, lapce, teehee, lapce, etc.)
```bash
hx ~/.bashrc
```
or in some systems it may be called 'bash_profile'

3. Add an "alias" for your executable at the end of your bash file. Replace /path/to/your_executable with the path of your executable. And replace "your_keyword" with whatever you want to call File Fantastic by typing into your terminal. Add this line (with your details put in):
```text
alias your_keyword='/path/to/your_executable'
```
e.g. add:
```text
alias uma='/home/COMPUTERNAME/uma_tools/uma'
```

4. Save and close the text editor.
- If you used nano, you can do this by pressing: Ctrl x s (control key, x key, s key)
- If you use Helix(hx), Vim(vi), or Teehee: 'i' to type, then esc for normal mode, then :wq to write and quit

5. Reload the bash-shell configuration file, and maybe open a new terminal, to apply and use the changes.
```bash
source ~/.bashrc
```
or bash_profile

Now you should be able to launch Uma by typing 'uma' (or whatever name you choose) into a terminal.
