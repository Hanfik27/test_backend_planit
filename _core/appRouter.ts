import { createTRPCRouter } from "./trpc";

import { authRouter } from "./authRouter";
import { projectRouter } from "./projectRouter";
import { systemRouter } from "./systemRouter";
import { tagRouter } from "./tagRouter";
import { taskRouter } from "./taskRouter";
import { notificationRouter } from "./notificationRouter";

export const appRouter = createTRPCRouter({
  auth: authRouter,
  project: projectRouter,
  system: systemRouter,
  tag: tagRouter,
  task: taskRouter,
  notification: notificationRouter,
});

export type AppRouter = typeof appRouter;
