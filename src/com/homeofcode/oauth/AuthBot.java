package com.homeofcode.oauth;

import com.homeofcode.discord.DiscordEventHandler;
import com.homeofcode.discord.DiscordSimpleBot;
import discord4j.core.event.domain.lifecycle.ReadyEvent;
import discord4j.core.event.domain.message.MessageCreateEvent;
import discord4j.core.object.entity.User;
import discord4j.core.object.entity.channel.TextChannel;
import discord4j.core.spec.MessageCreateSpec;

import java.sql.Date;
import java.sql.SQLException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.INFO;

public class AuthBot extends DiscordSimpleBot {
    static System.Logger LOG = System.getLogger(AuthBot.class.getPackageName());
    AuthServer authServer;
    User self;

    public AuthBot(AuthServer authServer, String token) {
        super(token);
        this.authServer = authServer;
    }

    @DiscordEventHandler(event = MessageCreateEvent.class)
    public void onMessageCreateEvent(MessageCreateEvent event) {
        var message = event.getMessage();
        if (!message.getAuthor().isPresent()) return; // skip anonymous messages
        var author = message.getAuthor().get();
        if (author.equals(self)) return; // skip our messages
        var channel = message.getChannel().block();
        if (channel == null) {
            LOG.log(System.Logger.Level.ERROR, "got a null channel for " + message);
            return;
        }
        var channelType = channel.getType();
        var mentioned = message.getUserMentions().contains(self);
        switch (channelType) {
            case DM -> {
                channel.createMessage("sorry, i only respond to verify messages in server channels.").block();
                return;
            }
            case GROUP_DM -> {
                if (mentioned) {
                    channel.createMessage("sorry, i only respond to verify messages in server channels.").block();
                }
                return;
            }
            case GUILD_TEXT -> {
            }
            default -> {
                return;
            }

        }

        if (message.getUserMentions().contains(self)) {
            final TextChannel textChannel = (TextChannel) channel;
//            message.addReaction(ReactionEmoji.unicode("\u2764")).block();
            if (message.getContent().contains("verify")) {
                final var privateChannel = author.getPrivateChannel().block();
                if (privateChannel == null) {
                    textChannel.createMessage(
                            MessageCreateSpec.create().withContent("i can't seem to get a private channel for you.")
                                    .withMessageReference(message.getId())).block();
                    return;
                }
                final var nr = authServer.createValidation();

                final var guild = textChannel.getGuild().block();
                if (guild == null) {
                    privateChannel.createMessage(
                            "sorry, you don't seem to have sent this message from a server channel").block();
                    return;
                }

                privateChannel.createMessage(String.format("please verify your id using %s",
                                authServer.getValidateURL(nr))).block();

//                message.delete().doOnError(t -> LOG.log(System.Logger.Level.ERROR, "couldn't delete message", t))
//                        .block();

                // once
                nr.future().thenAccept(email -> {
                    if (email == null) {
                        privateChannel.createMessage("verification failed").block();
                    } else {
                        try {
                            authServer.updateAuthRecord(author.getId().asString(), author.getUsername(), email,
                                    new Date(System.currentTimeMillis()));
                            privateChannel.createMessage(
                                    String.format("your email has been verified as %s on %s", email,
                                            guild.getName())).block();
                            LOG.log(INFO, "{0} ({1}) authenticated with email {2}",
                                    author.getUsername(),
                                    author.getId().asString(), email);
                            guild.getRoles().doOnEach(r -> {
                                var role = r.get();
                                if (role != null) {
                                    // we are looking for the
                                    if (role.getName().equalsIgnoreCase(authServer.authDomain)) {
                                        // add the role to the user by converting to member first
                                        // the onEach should really only execute once since it would be weird if a
                                        // user were a member of the same guild twice...
                                        var member = author.asMember(guild.getId());
                                        member.flatMap(m -> m.addRole(role.getId())).block();
                                    }
                                }
                            }).blockLast(); // getRoles().doOnEach
                        } catch (SQLException e) {
                            privateChannel.createMessage("problem recording to database.").block();
                        }
                    }
                });
            }
        }
    }

    @DiscordEventHandler(event = ReadyEvent.class)
    public void onReadyEvent(ReadyEvent event) {
        this.self = event.getSelf();
        LOG.log(DEBUG, "I am " + self);
        event.getClient().getGuilds().all(p -> {
            LOG.log(DEBUG, "in guild {0}", p.getName());
            return true;
        }).block();
        LOG.log(INFO, "Logged in as {0}#{1}", self.getUsername(), self.getDiscriminator());
    }

    private void periodic() {
    }

    public void startBot() {
        super.startBot();
        ScheduledExecutorService sched = Executors.newScheduledThreadPool(1);
        sched.scheduleAtFixedRate(this::periodic, 10, 10, TimeUnit.SECONDS);
    }
}