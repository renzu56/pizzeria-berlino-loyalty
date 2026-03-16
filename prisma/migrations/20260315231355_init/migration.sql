-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('admin', 'customer');

-- CreateEnum
CREATE TYPE "SubmissionType" AS ENUM ('review', 'tiktok', 'custom');

-- CreateEnum
CREATE TYPE "SubmissionStatus" AS ENUM ('pending', 'approved', 'rejected');

-- CreateEnum
CREATE TYPE "VoucherStatus" AS ENUM ('open', 'used');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "role" "UserRole" NOT NULL DEFAULT 'customer',
    "verified" BOOLEAN NOT NULL DEFAULT false,
    "verifyToken" TEXT,
    "walletToken" TEXT NOT NULL,
    "points" INTEGER NOT NULL DEFAULT 0,
    "pizzaCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TaskState" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "clickedAt" TIMESTAMP(3),
    "claimedAt" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'idle',

    CONSTRAINT "TaskState_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Submission" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "SubmissionType" NOT NULL,
    "taskId" TEXT,
    "link" TEXT NOT NULL,
    "status" "SubmissionStatus" NOT NULL DEFAULT 'pending',
    "rewardPoints" INTEGER NOT NULL DEFAULT 0,
    "note" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reviewedAt" TIMESTAMP(3),
    "reviewedBy" TEXT,

    CONSTRAINT "Submission_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Event" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "points" INTEGER NOT NULL DEFAULT 0,
    "pizzas" INTEGER NOT NULL DEFAULT 0,
    "note" TEXT NOT NULL,
    "meta" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "dayKey" TEXT NOT NULL,

    CONSTRAINT "Event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Voucher" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "status" "VoucherStatus" NOT NULL DEFAULT 'open',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "usedAt" TIMESTAMP(3),
    "usedBy" TEXT,
    "meta" JSONB,

    CONSTRAINT "Voucher_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdminCode" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "addPoints" INTEGER NOT NULL DEFAULT 0,
    "addPizzas" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL,
    "usedAt" TIMESTAMP(3),
    "usedByUserId" TEXT,

    CONSTRAINT "AdminCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CustomTask" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "targetUrl" TEXT,
    "points" INTEGER NOT NULL DEFAULT 0,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL,

    CONSTRAINT "CustomTask_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScannerConfig" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "label" TEXT NOT NULL DEFAULT 'Daily Check-in',
    "addPoints" INTEGER NOT NULL DEFAULT 10,
    "addPizzas" INTEGER NOT NULL DEFAULT 0,
    "oncePerDay" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "ScannerConfig_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_verifyToken_key" ON "User"("verifyToken");

-- CreateIndex
CREATE UNIQUE INDEX "User_walletToken_key" ON "User"("walletToken");

-- CreateIndex
CREATE UNIQUE INDEX "TaskState_userId_type_key" ON "TaskState"("userId", "type");

-- CreateIndex
CREATE INDEX "Submission_status_createdAt_idx" ON "Submission"("status", "createdAt");

-- CreateIndex
CREATE INDEX "Submission_userId_type_idx" ON "Submission"("userId", "type");

-- CreateIndex
CREATE INDEX "Event_userId_createdAt_idx" ON "Event"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "Event_userId_dayKey_idx" ON "Event"("userId", "dayKey");

-- CreateIndex
CREATE UNIQUE INDEX "Voucher_code_key" ON "Voucher"("code");

-- CreateIndex
CREATE INDEX "Voucher_userId_status_idx" ON "Voucher"("userId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "AdminCode_code_key" ON "AdminCode"("code");

-- AddForeignKey
ALTER TABLE "TaskState" ADD CONSTRAINT "TaskState_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Submission" ADD CONSTRAINT "Submission_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Event" ADD CONSTRAINT "Event_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Voucher" ADD CONSTRAINT "Voucher_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
