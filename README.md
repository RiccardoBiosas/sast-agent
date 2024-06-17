# Install and Run
- Install Poetry
```sh
curl -sSL https://install.python-poetry.org | python3 -
```
- Install the project dependencies
```sh
cd sast-agent
poetry install
```
- Create .env file and set `OPENAI_TOKEN` to your OpenAI API key
```sh
cp .env.example .env
```
- Run the CLI
```sh
poetry run python main.py
```