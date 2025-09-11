from utils.router import MainRouter, DbRouter


class MovementRouter(MainRouter, DbRouter):
    def get_choices(self):
        return ['Start all',
                'Start chain',
                'Daily tasks']

    def route(self, task, action):
        return dict(zip(self.get_choices(), [task.main,
                                             task.chain,
                                             task.daily_tasks]))[action]

    @property
    def action(self):
        self.start_db_router()
        return self.get_action()
